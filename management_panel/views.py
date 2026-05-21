from pathlib import Path

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import render, redirect
from prometheus_client import CollectorRegistry, Gauge, generate_latest, CONTENT_TYPE_LATEST

from .services import guard_logic


def index(request):
    static_dir = Path(__file__).resolve().parent / "static" / "management_panel"

    if not guard_logic.audit_log:
        guard_logic.run_demo_requests()

    if request.method == "POST":
        try:
            action = request.POST.get("action")
            role = request.POST.get("role")
            actor = request.POST.get("actor", "").strip() or "Неизвестный пользователь"

            payload = {
                "request_id": len(guard_logic.audit_log) + 1,
                "actor": actor,
                "role": role,
                "action": action,
                "approved": request.POST.get("approved") == "on",
            }

            if action == "change_resources":
                payload["new_cpu"] = int(request.POST.get("new_cpu"))
                payload["new_memory"] = int(request.POST.get("new_memory"))

            elif action == "change_routing":
                payload["new_route"] = request.POST.get("new_route")

            elif action == "restart_critical_component":
                payload["simulate_failure"] = request.POST.get("simulate_failure") == "on"

            elif action == "check_certificate":
                payload["certificate_valid"] = request.POST.get("certificate_valid") == "on"

            elif action == "detect_insecure_http":
                payload["protocol"] = request.POST.get("protocol", "http")

            record = guard_logic.submit_request(payload)

            messages.success(
                request,
                f"Запрос обработан. Решение: {record['decision']}. Причина: {record['reason']}"
            )
            return redirect("index")

        except Exception as e:
            messages.error(request, f"Ошибка обработки запроса: {e}")
            return redirect("index")

    context = guard_logic.get_dashboard_context(static_dir)
    return render(request, "management_panel/index.html", context)


def reset_demo(request):
    guard_logic.reset_demo_data()
    guard_logic.run_demo_requests()
    messages.info(request, "Демонстрационный сценарий выполнен заново.")
    return redirect("index")


def metrics(request):
    if not guard_logic.audit_log:
        guard_logic.run_demo_requests()

    registry = CollectorRegistry()
    quality_metrics = guard_logic.get_quality_metrics()

    descriptions = {
        "management_panel_requests_total": "Total number of processed management requests",
        "management_panel_allow_total": "Number of allowed management actions",
        "management_panel_deny_total": "Number of denied management actions",
        "management_panel_rollback_total": "Number of rollback decisions",
        "management_panel_availability_status": "Current system availability status",
        "management_panel_audit_log_records_total": "Number of audit log records",
        "management_panel_https_enabled_status": "HTTPS enabled status",
        "management_panel_certificate_valid_status": "Certificate validity status",
        "management_panel_insecure_http_detected_status": "Detected insecure HTTP access status",
        "management_panel_quality_score": "Integrated software quality score",
    }

    for metric_name, metric_value in quality_metrics.items():
        metric = Gauge(
            metric_name,
            descriptions.get(metric_name, "Software quality metric"),
            registry=registry
        )
        metric.set(float(metric_value))

    return HttpResponse(generate_latest(registry), content_type=CONTENT_TYPE_LATEST)
