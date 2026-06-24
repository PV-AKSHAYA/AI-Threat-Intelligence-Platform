from app.services.detection_rules import generate_detection_rules
from app.schemas.schemas import IOC

rules = generate_detection_rules(
    [
        IOC(type="domain", value="secure-login-update.com"),
        IOC(type="ipv4", value="45.33.32.156"),
    ],
    []
)

print(rules.sigma)
print(rules.splunk)