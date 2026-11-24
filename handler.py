from mangum import Mangum
from app.main import app

# Mangum adapter for AWS Lambda serverless execution (Free Tier)
handler = Mangum(app, lifespan="off")
