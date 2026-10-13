"""Simulated tools. Nothing here has real side effects."""
PRIVILEGED = {"issue_refund", "delete_user", "transfer_funds"}

REGISTRY = {
    "lookup_order": lambda a: "Order status: shipped",
    "issue_refund": lambda a: f"Refund issued ({a})",
    "delete_user": lambda a: f"User deleted ({a})",
    "transfer_funds": lambda a: f"Funds transferred ({a})",
}
