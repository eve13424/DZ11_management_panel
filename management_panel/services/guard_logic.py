
import copy
from pathlib import Path
from datetime import datetime

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


INITIAL_STATE = {
    "service_running": True,
    "routing_ok": True,
    "cpu_limit": 6,
    "memory_limit": 12,
    "self_healing": True,
    "critical_component_running": True,
    "https_enabled": False,
    "certificate_valid": False,
    "http_redirect_enabled": False,
    "hsts_enabled": False,
    "insecure_http_detected": False,
}

role_permissions = {
    "change_resources": ["admin_customer"],
    "change_routing": ["admin_customer", "operator_provider"],
    "disable_self_healing": ["admin_customer"],
    "restart_critical_component": ["admin_customer", "operator_provider"],
    "read_audit": ["admin_customer", "auditor"],
    "enable_https": ["admin_customer"],
    "check_certificate": ["admin_customer", "auditor"],
    "enable_http_redirect": ["admin_customer"],
    "enable_hsts": ["admin_customer"],
    "detect_insecure_http": ["admin_customer", "auditor"],
}

critical_actions = [
    "change_resources",
    "change_routing",
    "disable_self_healing",
    "restart_critical_component",
    "enable_https",
    "enable_http_redirect",
    "enable_hsts",
]

allowed_routes = ["private-cloud-gw", "backup-gw"]

requests_queue = [
    {
        "request_id": 1,
        "actor": "Иманбаева Э.Е.",
        "role": "admin_customer",
        "action": "change_resources",
        "new_cpu": 8,
        "new_memory": 16,
        "approved": True,
    },
    {
        "request_id": 2,
        "actor": "Оператор поставщика",
        "role": "operator_provider",
        "action": "change_routing",
        "new_route": "private-cloud-gw",
        "approved": True,
    },
    {
        "request_id": 3,
        "actor": "Оператор поставщика",
        "role": "operator_provider",
        "action": "disable_self_healing",
        "approved": False,
    },
    {
        "request_id": 4,
        "actor": "Иманбаева Э.Е.",
        "role": "admin_customer",
        "action": "enable_https",
        "approved": True,
    },
    {
        "request_id": 5,
        "actor": "Аудитор",
        "role": "auditor",
        "action": "read_audit",
        "approved": False,
    },
]

current_state = copy.deepcopy(INITIAL_STATE)
audit_log = []
history = []


def check_availability(state):
    return (
        state["service_running"]
        and state["routing_ok"]
        and state["self_healing"]
        and state["critical_component_running"]
        and state["cpu_limit"] >= 2
        and state["memory_limit"] >= 4
    )


def get_secure_access_status(state):
    return int(
        state.get("https_enabled", False)
        and state.get("certificate_valid", False)
        and state.get("http_redirect_enabled", False)
        and not state.get("insecure_http_detected", False)
    )


def get_status(state):
    return {
        "service_running": state["service_running"],
        "routing_ok": state["routing_ok"],
        "cpu_limit": state["cpu_limit"],
        "memory_limit": state["memory_limit"],
        "self_healing": state["self_healing"],
        "critical_component_running": state["critical_component_running"],
        "https_enabled": state["https_enabled"],
        "certificate_valid": state["certificate_valid"],
        "http_redirect_enabled": state["http_redirect_enabled"],
        "hsts_enabled": state["hsts_enabled"],
        "insecure_http_detected": state["insecure_http_detected"],
        "available": int(check_availability(state)),
        "secure_access": get_secure_access_status(state),
    }


def role_allowed(action, role):
    return role in role_permissions.get(action, [])


def policy_check(state, request_data):
    action = request_data["action"]

    if action == "change_resources":
        if request_data["new_cpu"] < 2 or request_data["new_memory"] < 4:
            return False, "Недопустимые лимиты ресурсов"
        return True, "Ресурсы соответствуют политике доступности"

    if action == "change_routing":
        if request_data["new_route"] not in allowed_routes:
            return False, "Маршрут не входит в допустимый перечень"
        return True, "Маршрут допустим"

    if action == "disable_self_healing":
        return False, "Отключение самовосстановления запрещено"

    if action == "restart_critical_component":
        return True, "Перезапуск критичного компонента разрешен"

    if action == "read_audit":
        return True, "Чтение журнала разрешено"

    if action == "enable_https":
        return True, "Включение HTTPS разрешено"

    if action == "check_certificate":
        return True, "Проверка сертификата разрешена"

    if action == "enable_http_redirect":
        if not state.get("https_enabled", False):
            return False, "Сначала необходимо включить HTTPS"
        return True, "Перенаправление HTTP на HTTPS разрешено"

    if action == "enable_hsts":
        if not state.get("https_enabled", False):
            return False, "HSTS нельзя включить до включения HTTPS"
        return True, "Включение HSTS разрешено"

    if action == "detect_insecure_http":
        return True, "Проверка небезопасного HTTP-доступа разрешена"

    return False, "Неизвестная операция"


def apply_action(state, request_data):
    new_state = copy.deepcopy(state)
    action = request_data["action"]

    if action == "change_resources":
        new_state["cpu_limit"] = request_data["new_cpu"]
        new_state["memory_limit"] = request_data["new_memory"]

    elif action == "change_routing":
        new_state["routing_ok"] = request_data["new_route"] in allowed_routes

    elif action == "disable_self_healing":
        new_state["self_healing"] = False

    elif action == "restart_critical_component":
        new_state["critical_component_running"] = False
        if request_data.get("simulate_failure", False):
            new_state["service_running"] = False
        else:
            new_state["critical_component_running"] = True

    elif action == "enable_https":
        new_state["https_enabled"] = True

    elif action == "check_certificate":
        new_state["certificate_valid"] = request_data.get("certificate_valid", True)

    elif action == "enable_http_redirect":
        new_state["http_redirect_enabled"] = True

    elif action == "enable_hsts":
        new_state["hsts_enabled"] = True

    elif action == "detect_insecure_http":
        protocol = request_data.get("protocol", "http")
        new_state["insecure_http_detected"] = protocol.lower() == "http"

    return new_state


def process_request(state, request_data):
    old_state = copy.deepcopy(state)
    before = get_status(state)

    decision = "deny"
    reason = ""
    recovery = "Не требуется"

    if not role_allowed(request_data["action"], request_data["role"]):
        reason = "Роль не имеет полномочий"

    elif request_data["action"] in critical_actions and not request_data.get("approved", False):
        reason = "Нет второго подтверждения"

    else:
        allowed, message = policy_check(state, request_data)
        if not allowed:
            reason = message
        else:
            changed_state = apply_action(state, request_data)

            if not check_availability(changed_state):
                decision = "rollback"
                reason = "После изменения нарушена доступность"
                recovery = "Выполнен откат к предыдущей конфигурации"
                state = old_state
            else:
                decision = "allow"
                reason = message
                state = changed_state

    after = get_status(state)

    log_record = {
        "request_id": request_data["request_id"],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": request_data["actor"],
        "role": request_data["role"],
        "action": request_data["action"],
        "decision": decision,
        "reason": reason,
        "approved": int(request_data.get("approved", False)),
        "availability_before": before["available"],
        "availability_after": after["available"],
        "secure_access_before": before["secure_access"],
        "secure_access_after": after["secure_access"],
        "cpu_before": before["cpu_limit"],
        "cpu_after": after["cpu_limit"],
        "memory_before": before["memory_limit"],
        "memory_after": after["memory_limit"],
        "recovery": recovery,
    }

    return state, log_record


def submit_request(request_data):
    global current_state, audit_log, history

    current_state, record = process_request(current_state, request_data)
    audit_log.append(record)

    status = get_status(current_state)
    history.append({
        "step": request_data["request_id"],
        "available": status["available"],
        "secure_access": status["secure_access"],
        "cpu_limit": current_state["cpu_limit"],
        "memory_limit": current_state["memory_limit"],
    })

    return record


def reset_demo_data():
    global current_state, audit_log, history
    current_state = copy.deepcopy(INITIAL_STATE)
    audit_log = []
    history = []


def run_demo_requests():
    if audit_log:
        return
    for request_item in requests_queue:
        submit_request(request_item)


def build_dataframes():
    audit_df = pd.DataFrame(audit_log)
    history_df = pd.DataFrame(history)

    if audit_df.empty:
        summary_df = pd.DataFrame(columns=["decision", "count"])
    else:
        summary_df = (
            audit_df.groupby("decision")
            .size()
            .to_frame("count")
            .reset_index()
            .sort_values(by="count", ascending=False)
        )

    return audit_df, history_df, summary_df


def save_charts(static_dir):
    static_path = Path(static_dir)
    static_path.mkdir(parents=True, exist_ok=True)

    _, history_df, summary_df = build_dataframes()

    plt.figure(figsize=(8, 5))
    if not summary_df.empty:
        plt.bar(summary_df["decision"], summary_df["count"])
    plt.title("Количество решений контейнера")
    plt.xlabel("Тип решения")
    plt.ylabel("Число запросов")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(static_path / "chart_decisions.png")
    plt.close()

    plt.figure(figsize=(8, 5))
    if not history_df.empty:
        plt.plot(history_df["step"], history_df["available"], marker="o")
    plt.title("Доступность системы по шагам")
    plt.xlabel("Шаг")
    plt.ylabel("Доступность")
    plt.yticks([0, 1])
    plt.grid(linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(static_path / "chart_availability.png")
    plt.close()

    plt.figure(figsize=(8, 5))
    if not history_df.empty:
        plt.plot(history_df["step"], history_df["cpu_limit"], marker="o", label="CPU")
        plt.plot(history_df["step"], history_df["memory_limit"], marker="s", label="RAM")
        plt.legend()
    plt.title("Изменение лимитов ресурсов")
    plt.xlabel("Шаг")
    plt.ylabel("Значение")
    plt.grid(linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(static_path / "chart_resources.png")
    plt.close()


def get_quality_metrics():
    total_requests = len(audit_log)

    allow_count = sum(1 for row in audit_log if row.get("decision") == "allow")
    deny_count = sum(1 for row in audit_log if row.get("decision") == "deny")
    rollback_count = sum(1 for row in audit_log if row.get("decision") == "rollback")

    status = get_status(current_state)

    availability_status = int(status.get("available", 0))
    audit_records_count = len(audit_log)
    https_enabled_status = int(current_state.get("https_enabled", False))
    certificate_valid_status = int(current_state.get("certificate_valid", False))
    insecure_http_detected_status = int(current_state.get("insecure_http_detected", False))

    if total_requests > 0:
        allow_rate = allow_count / total_requests
        rollback_rate = rollback_count / total_requests
    else:
        allow_rate = 1
        rollback_rate = 0

    audit_completeness = 1 if audit_records_count == total_requests else 0

    quality_score = round(
        0.4 * availability_status
        + 0.2 * allow_rate
        + 0.2 * (1 - rollback_rate)
        + 0.2 * audit_completeness,
        3
    )

    return {
        "management_panel_requests_total": total_requests,
        "management_panel_allow_total": allow_count,
        "management_panel_deny_total": deny_count,
        "management_panel_rollback_total": rollback_count,
        "management_panel_availability_status": availability_status,
        "management_panel_audit_log_records_total": audit_records_count,
        "management_panel_https_enabled_status": https_enabled_status,
        "management_panel_certificate_valid_status": certificate_valid_status,
        "management_panel_insecure_http_detected_status": insecure_http_detected_status,
        "management_panel_quality_score": quality_score,
    }


def get_dashboard_context(static_dir):
    save_charts(static_dir)

    audit_df, history_df, summary_df = build_dataframes()
    status = get_status(current_state)
    roles = sorted({role for role_list in role_permissions.values() for role in role_list})

    return {
        "system_status": status,
        "audit_rows": audit_df.to_dict(orient="records"),
        "history_rows": history_df.to_dict(orient="records"),
        "summary_rows": summary_df.to_dict(orient="records"),
        "roles": roles,
        "actions": list(role_permissions.keys()),
        "routes": allowed_routes,
        "quality_metrics": get_quality_metrics(),
        "chart_version": datetime.now().strftime("%Y%m%d%H%M%S"),
    }