"""Workspace + validation-to-finding bridge tests."""
from pentest_workstation.app.validation import DetectionContext, HttpExchange


def test_engagement_target_finding_flow(context):
    eng = context.workspace.create_engagement("Eng", authorization_note="ok")
    tgt = context.workspace.add_target(eng.id, "app", base_url="https://app.test",
                                       authorized=True, scope_include=["app.test"])
    assert tgt.authorized
    f = context.workspace.create_finding(eng.id, "Manual finding", severity="medium")
    assert context.workspace.count_findings() == 1
    context.workspace.add_evidence(f.id, label="note", notes="something")
    assert len(context.workspace.get_finding(f.id).evidence) == 1


def test_record_validation_preserves_verdict(context):
    eng = context.workspace.create_engagement("Eng2", authorization_note="ok")
    marker = "zz<script>window['__PENLAB_XSS__']=true</script>"
    ctx = DetectionContext(payload=marker, marker=marker,
                           test=HttpExchange(status=200, body=f"<div>{marker}</div>",
                                             response_headers={"Content-Type": "text/html"}),
                           runtime_executed=True)
    res = context.execution.validate("reflected_xss", ctx)
    ev = context.execution.validation.build_evidence(res, ctx)
    finding = context.workspace.record_validation(eng.id, "XSS", res, ctx,
                                                  severity="high", evidence_fields=ev)
    # status/confidence must come straight from the evidence-based verdict
    assert finding.status == res.status.value == "confirmed"
    assert finding.confidence == res.confidence.value
    assert context.workspace.count_findings(actionable_only=True) == 1


def test_actionable_count_excludes_suspected(context):
    eng = context.workspace.create_engagement("Eng3", authorization_note="ok")
    marker = "zz<script>x</script>"
    ctx = DetectionContext(payload=marker, marker=marker,
                           test=HttpExchange(status=200, body=f"<div>{marker}</div>",
                                             response_headers={"Content-Type": "text/html"}))
    res = context.execution.validate("reflected_xss", ctx)  # suspected (no runtime)
    context.workspace.record_validation(eng.id, "XSS?", res, ctx, severity="high",
                                        evidence_fields={"label": "e"})
    assert context.workspace.count_findings() == 1
    assert context.workspace.count_findings(actionable_only=True) == 0
