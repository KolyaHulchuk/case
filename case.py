import csv
from collections import defaultdict
from datetime import date
from pathlib import Path

# Припущення: дату рев'ю в завданні не вказано.
# Найновіший last_login в accounts.csv — 2026-11-12,
# тому вважаю, що рев'ю проводиться наступного дня.
REVIEW_DATE = date(2026, 11, 13)

INACTIVITY_LIMIT_DAYS = 90
CORPORATE_DOMAIN = "@paytest.ua"

SCRIPT_DIR = Path(__file__).resolve().parent
EMPLOYEES_FILE = SCRIPT_DIR / "employees.csv"
ACCOUNTS_FILE = SCRIPT_DIR / "accounts.csv"
FINDINGS_FILE = SCRIPT_DIR / "findings.csv"

ROLE_MODEL = {
    "Support L1": {"BO": "viewer", "GitLab": None, "GCP-prod": None},
    "Support L2": {"BO": "operator", "GitLab": None, "GCP-prod": None},
    "Finance Analyst": {"BO": "finance", "GitLab": None, "GCP-prod": None},
    "Developer": {"BO": None, "GitLab": "developer", "GCP-prod": None},
    "DevOps": {"BO": None, "GitLab": "maintainer", "GCP-prod": "roles/editor"},
    "Security Analyst": {"BO": "auditor", "GitLab": None, "GCP-prod": "roles/iam.securityReviewer"},
}


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def build_employee_lookup(employees):
    employees_by_email = {}
    for employee in employees:
        employees_by_email[employee["email"]] = employee
    return employees_by_email


def parse_date(text):
    if not text:
        return None
    return date.fromisoformat(text)


def find_possible_owner(account, employees_by_email):
    name_part = (account["email"] or account["login"]).split("@")[0]
    for email, employee in employees_by_email.items():
        if email.split("@")[0] == name_part:
            return employee
    return None


def check_hr_match(account, employee, employees_by_email):
    if employee is not None:
        return None
    email = account["email"] or "(порожній)"
    problem = f"немає запису в HR для email {email} - акаунт не прив'язаний до працівника"
    owner = find_possible_owner(account, employees_by_email)
    if owner is not None:
        problem += f" (можливий власник за ім'ям: {owner['name']}, {owner['position']}, {owner['email']})"
    return problem


def check_employee_status(employee):
    if employee is None:
        return None
    if employee["status"] == "terminated":
        return f"працівника звільнено {employee['status_date']}, акаунт досі існує"
    if employee["status"] == "leave":
        return f"працівник у відпустці з {employee['status_date']}, акаунт досі існує"
    return None


def check_login_after_status_change(account, employee):
    if employee is None or employee["status"] == "active":
        return None
    status_date = parse_date(employee["status_date"])
    last_login = parse_date(account["last_login"])
    if status_date is None or last_login is None:
        return None
    if last_login > status_date:
        return (f"останній вхід {last_login} ПІСЛЯ дати статусу '{employee['status']}' "
                f"({status_date})")
    return None


def check_role_vs_position(account, employee):
    if employee is None:
        return None
    position = employee["position"]
    system = account["system"]
    actual_role = account["role"]
    if position not in ROLE_MODEL:
        return f"посади '{position}' немає в ролевій моделі - роль перевірити неможливо"
    expected_role = ROLE_MODEL[position][system]
    if expected_role is None:
        return f"має роль '{actual_role}', але {position} не повинен мати доступу до {system}"
    if actual_role != expected_role:
        return f"має роль '{actual_role}', очікувана роль для {position} - '{expected_role}'"
    return None


def check_permanent_admin(account):
    if account["system"] == "BO" and account["role"] == "admin":
        return "постійний admin-акаунт у BO (admin видається лише через PAM на час роботи)"
    return None


def check_inactive(account):
    last_login = parse_date(account["last_login"])
    if last_login is None:
        return "немає даних про останній вхід - активність перевірити неможливо"
    days_unused = (REVIEW_DATE - last_login).days
    if days_unused > INACTIVITY_LIMIT_DAYS:
        return (f"не використовується {days_unused} дн. (останній вхід {last_login}), "
                f"ліміт {INACTIVITY_LIMIT_DAYS} дн. - має бути заблокований")
    return None


def check_corporate_email(account):
    email = account["email"]
    if not email:
        return "немає email - акаунт не прив'язаний до корпоративної пошти"
    if not email.lower().endswith(CORPORATE_DOMAIN):
        return f"email {email} не є корпоративною адресою {CORPORATE_DOMAIN}"
    return None


def review_account(account, employees_by_email):
    employee = employees_by_email.get(account["email"])
    results = [
        check_hr_match(account, employee, employees_by_email),
        check_employee_status(employee),
        check_login_after_status_change(account, employee),
        check_role_vs_position(account, employee),
        check_permanent_admin(account),
        check_inactive(account),
        check_corporate_email(account),
    ]
    problems = []
    for problem in results:
        if problem is not None:
            problems.append(problem)
    return problems


def check_sod(accounts):
    bo_roles_by_email = defaultdict(set)
    for account in accounts:
        if account["system"] == "BO" and account["email"]:
            bo_roles_by_email[account["email"]].add(account["role"])

    findings = []
    for email, roles in bo_roles_by_email.items():
        if "operator" in roles and "refund_approver" in roles:
            findings.append({
                "system": "BO",
                "login": email,
                "problem": "конфлікт SoD: може і створювати (operator), і підтверджувати (refund_approver) повернення",
            })
    return findings


def print_findings(findings):
    print(f"Access review, review date (assumption): {REVIEW_DATE}")
    print(f"{'SYSTEM':<9} {'LOGIN':<24} PROBLEM")
    for finding in findings:
        print(f"{finding['system']:<9} {finding['login']:<24} {finding['problem']}")
    print(f"Total findings: {len(findings)}")


def save_findings(findings, path):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["system", "login", "problem"])
        writer.writeheader()
        writer.writerows(findings)


def main():
    employees_by_email = build_employee_lookup(read_csv(EMPLOYEES_FILE))
    accounts = read_csv(ACCOUNTS_FILE)

    findings = []
    for account in accounts:
        for problem in review_account(account, employees_by_email):
            findings.append({
                "system": account["system"],
                "login": account["login"],
                "problem": problem,
            })
    findings.extend(check_sod(accounts))

    print_findings(findings)
    save_findings(findings, FINDINGS_FILE)
    print(f"Saved to {FINDINGS_FILE}")


if __name__ == "__main__":
    main()
