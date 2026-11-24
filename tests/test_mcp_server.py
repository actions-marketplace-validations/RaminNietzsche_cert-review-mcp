"""MCP server: in-process calls plus a real stdio round trip."""
import asyncio
import json
import sys

import pytest

from cert_review.mcp_server import build_server

EXPECTED_TOOLS = {"list_rules", "get_rule", "search_rules", "check_files", "check_diff", "explain_finding",
                  "build_review_packet", "validate_findings", "get_rule_coverage", "format_findings",
                  "format_pr_review", "review_pr"}


def _text(result):
    if isinstance(result, tuple):          # mcp 1.x: (content, structured)
        result = result[0]
    content = result.content if hasattr(result, "content") else result
    return content[0].text


def test_tools_resources_prompts_registered():
    s = build_server()

    async def go():
        tools = {t.name for t in await s.list_tools()}
        templates = {getattr(t, "uri_template", None) or t.uriTemplate for t in await s.list_resource_templates()}
        prompts = {p.name for p in await s.list_prompts()}
        return tools, templates, prompts
    tools, templates, prompts = asyncio.run(go())
    assert tools == EXPECTED_TOOLS
    assert len(tools) >= 12
    assert {"rule://{rule_id}", "profile://{name}"} <= templates
    assert {"cert_review", "ceph_review"} <= prompts


def test_explain_and_list_in_process():
    s = build_server()

    async def go():
        a = json.loads(_text(await s.call_tool("get_rule", {"rule_id": "EXP34-C"})))
        b = json.loads(_text(await s.call_tool(
            "list_rules", {"lang": "cpp", "coverage": "deterministic", "limit": 100})))
        c = json.loads(_text(await s.call_tool("get_rule_coverage", {"lang": "cpp"})))
        return a, b, c
    a, b, c = asyncio.run(go())
    assert a["risk"]["priority"] == "P18" and a["coverage"]["checkers"]
    want = c["all_mappings"]["deterministic"]   # the filter matches either tier
    assert b["count"] == want and all(r["lang"] == "cpp" for r in b["rules"])
    assert c["total"] == 83 and c["runnable_toolchain"]["deterministic"] == 18


def test_annotations_and_titles():
    s = build_server()

    async def go():
        return await s.list_tools()
    for t in asyncio.run(go()):
        d = t.model_dump(by_alias=True, exclude_none=True)
        a = d.get("annotations") or {}
        assert d.get("title") and d.get("description") and a
        assert a["readOnlyHint"] is True and a["destructiveHint"] is False
        assert a["idempotentHint"] is True and a["openWorldHint"] is False
        props = d["inputSchema"].get("properties", {})
        assert all(v.get("description") for v in props.values()), t.name


def test_review_pr_tool_has_github_footer_param():
    s = build_server()

    async def go():
        tools = await s.list_tools()
        rp = next(t for t in tools if t.name == "review_pr")
        schema = getattr(rp, "input_schema", None) or rp.model_dump(by_alias=True).get("inputSchema", {})
        return schema.get("properties", {})

    props = asyncio.run(go())
    assert "github_footer" in props
    assert "pull_request_target" in props["github_footer"].get("description", "")


def test_format_pr_review_tool_has_github_footer_param():
    s = build_server()

    async def go():
        tools = await s.list_tools()
        fp = next(t for t in tools if t.name == "format_pr_review")
        schema = getattr(fp, "input_schema", None) or fp.model_dump(by_alias=True).get("inputSchema", {})
        return schema.get("properties", {})

    assert "github_footer" in asyncio.run(go())


def test_prompts_forbid_posting():
    s = build_server()

    async def go():
        return await s.get_prompt("ceph_review", {"target": "my PR"})
    p = asyncio.run(go())
    text = json.dumps(p, default=str)
    assert "never post" in text.lower() and "ceph_assert" in text


def test_stdio_round_trip():
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go():
        params = StdioServerParameters(command=sys.executable, args=["-m", "cert_review.mcp_server"])
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                res = await session.call_tool("search_rules", {"query": "null pointer dereference", "limit": 3})
                rr = await session.read_resource("rule://EXP34-C")
                return tools, json.loads(res.content[0].text), rr
    try:
        tools, search, rr = asyncio.run(asyncio.wait_for(go(), 60))
    except Exception as e:     # SDK client API differs between releases; do not hide real failures
        pytest.skip(f"mcp client API unavailable: {type(e).__name__}: {e}") if "attribute" in str(e) else None
        raise
    assert tools == EXPECTED_TOOLS
    assert len(tools) >= 12
    assert any(x["id"] == "EXP34-C" for x in search["results"])
    assert "EXP34-C" in str(rr)


@pytest.mark.parametrize("tool,args,msg", [
    ("check_diff", {"repo": "."}, "provide base"),
    ("get_rule", {"rule_id": "XYZ99-C"}, "unknown rule"),
    ("check_files", {"path": "/nonexistent/cert-review"}, "path not found"),
    ("get_rule", {"rule_id": "EXP34-C", "profile": "nope"}, "Available profiles"),
    ("explain_finding", {"finding": {"rule_id": "XYZ99-C", "code": "x"}}, "unknown rule"),
    ("explain_finding", {"finding": {"rule_id": "ERR34-C", "file": "/nonexistent/a.c", "line": 1}}, "path not found"),
    ("check_files", {"path": ".", "baseline_path": "/nonexistent/b.json"}, "path not found"),
])
def test_errors_carry_a_message(tool, args, msg):
    s = build_server()
    with pytest.raises(Exception, match=msg):
        asyncio.run(s.call_tool(tool, args))


def test_explain_finding_in_process(tmp_path):
    f = tmp_path / "a.c"
    f.write_text("#include <stdlib.h>\nint p(const char *buff) {\n  return atoi(buff);\n}\n")
    s = build_server()

    async def go():
        return json.loads(_text(await s.call_tool("explain_finding", {"finding": {
            "rule_id": "ERR34-C", "file": str(f), "line": 3, "tool": "clang-tidy",
            "checker": "cert-err34-c", "severity": "warning", "message": "atoi"}})))
    d = asyncio.run(go())
    assert d["rule"]["id"] == "ERR34-C" and "strtol" in d["fix"]["summary"]
    assert d["example"]["noncompliant"]["code"] and d["why"]


def test_check_files_with_baseline(tmp_path):
    from cert_review import baseline as BL
    f = tmp_path / "a.c"
    f.write_text("#include <stdlib.h>\nint p(const char *s) { return atoi(s); }\n")
    bl = tmp_path / BL.DEFAULT_FILE
    BL.dump(BL.build([{"rule_id": "ERR34-C", "file": str(f), "line": 2}], tmp_path), bl)
    s = build_server()

    async def go():
        return json.loads(_text(await s.call_tool("check_files", {
            "path": str(f), "tools": ["clang-tidy"], "baseline_path": str(bl)})))
    d = asyncio.run(go())
    b = d["baseline"]
    assert b["entries"] == 1 and b["new"] == len(d["findings"])
    assert all(x["rule_id"] != "ERR34-C" for x in d["findings"])
    assert b["baselined"] + b["fixed"] == 1
