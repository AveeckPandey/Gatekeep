import logging
from mangum import Mangum
from app.main import app

# Configure logging for AWS CloudWatch
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gatekeep.lambda")

# Mangum ASGI adapter for AWS Lambda serverless execution (Free Tier)
# lifespan="off" is recommended for Lambda to prevent ASGI lifespan overhead on cold starts
handler = Mangum(app, lifespan="off")
