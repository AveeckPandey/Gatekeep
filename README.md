# GateKeep — Multi-Tenant LLM Security Gateway & Prompt Injection Firewall

[![AWS Free Tier](https://img.shields.io/badge/AWS-Free%20Tier%20%28%240%2Fmo%29-orange.svg)](https://aws.amazon.com/free/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%203.12+-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2016%20%28App%20Router%29-black.svg)](https://nextjs.org)
[![DynamoDB](https://img.shields.io/badge/Database-Amazon%20DynamoDB%20Single--Table-4053D6.svg)](https://aws.amazon.com/dynamodb/)
[![Tests](https://img.shields.io/badge/Pytest-38%20Passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

GateKeep is a production-grade, multi-tenant LLM Security Gateway, Prompt Injection Firewall, and PII Redaction Proxy designed to operate completely within the **AWS Free Tier ($0/month)**.

---

## Architecture Overview

GateKeep decouples security enforcement into two strictly isolated planes:

```
                                  [ Web Client / Browser ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [ Next.js Dashboard ]                       [ Client Application ]
             (Vercel Free Tier)                          (curl / OpenAI SDK)
                       │                                           │
                       │ JWT Bearer                                │ gw_live_... Key
                       ▼                                           ▼
        ┌─────────────────────────────┐             ┌─────────────────────────────┐
        │   CONTROL PLANE API         │             │   DATA PLANE PROXY          │
        │   /api/auth/*               │             │   POST /v1/chat/completions │
        │   /api/workspaces/*         │             └──────────────┬──────────────┘
        └──────────────┬──────────────┘                            │
                       │                                           ▼
                       │                            ┌─────────────────────────────┐
                       │                            │  Deterministic Firewall:    │
                       │                            │  • Regex PII & Secret Redac │
                       │                            │  • Luhn (Mod 10) Card Check │
                       │                            │  • Shannon Entropy Scanner  │
                       │                            │  • Prompt Injection Filter  │
                       │                            └──────────────┬──────────────┘
                       │                                           │
                       ▼                                           ▼
        ┌─────────────────────────────────────────────────────────────────────────┐
        │                 Amazon DynamoDB (Single-Table Design)                   │
        │                 On-Demand / Free Tier + 30-Day TTL Logs                 │
        └─────────────────────────────────────────────────────────────────────────┘
                                                           │
                                                           ▼ (Forward Clean / Redacted)
                                            ┌─────────────────────────────┐
                                            │ Upstream LLM: NVIDIA Build  │
                                            │ Nemotron / OpenAI (BYOK)    │
                                            └─────────────────────────────┘
```

### Two-Layer Architecture
1. **Control Plane (Management Dashboard):**
   - User authentication via JWT (or Amazon Cognito).
   - Strict multi-tenant BOLA/IDOR isolation: tenants can only access and modify their own workspaces, policies, keys, and logs.
   - Encrypted BYOK: Workspaces store their NVIDIA Nemotron / OpenAI API keys encrypted at rest using **Fernet (AES-128-CBC + HMAC-SHA256)**.
2. **Data Plane (High-Performance Proxy `/v1/chat/completions`):**
   - OpenAI-compatible chat proxy authenticating via workspace-scoped Gateway Keys (`gw_live_...`).
   - Keys are returned in plaintext only once upon creation and stored strictly as **SHA-256 hashes** ($O(1)$ DynamoDB hash partition lookup).
   - Inspects messages, applies workspace policy (`BLOCK`, `REDACT`, or `ALLOW`), records audit telemetry, and injects `aegisgate_meta`.

---

## AWS Free Tier ($0/month) Guarantee

GateKeep is engineered to incur **zero monthly cloud infrastructure fees**:
- **AWS Lambda:** 1,000,000 free requests per month and 3,200,000 seconds of compute time per month.
- **Lambda Function URLs:** $0/month (eliminates Amazon API Gateway costs completely).
- **Amazon DynamoDB:** 25 GB free storage, on-demand or 25 free RCU/WCU, with automated 30-day TTL data expiration.
- **Vercel:** Free Hobby tier for Next.js 16 frontend hosting.

---

## Project Structure

```
Gatekeep/
├── app/
│   ├── config.py                 # Pydantic environment configuration
│   ├── main.py                   # FastAPI application & CORS setup
│   ├── core/
│   │   ├── dependencies.py       # JWT & Gateway Key auth dependencies (BOLA/IDOR safe)
│   │   └── security.py           # Bcrypt hashing, JWT creation, Fernet encryption
│   ├── db/
│   │   └── dynamo.py             # DynamoDB client, resource, and schema creation
│   ├── models/                   # Pydantic domain models & OpenAI schemas
│   ├── repositories/
│   │   ├── base.py               # Abstract BaseRepository interface
│   │   ├── dynamo.py             # Single-Table DynamoDB repository
│   │   └── in_memory.py          # Fast in-memory repository for unit testing
│   ├── routes/
│   │   ├── auth.py               # /api/auth/register, /api/auth/login, /api/auth/me
│   │   ├── workspace.py          # Workspaces, Policies, API Keys, Audit Logs
│   │   └── proxy.py              # OpenAI-compatible /v1/chat/completions proxy
│   └── security/
│       ├── detector.py           # Core firewall inspection & redaction engine
│       └── rules.py              # Regex rules, Luhn algorithm, Injection heuristics
├── frontend/                     # Next.js 16 (App Router + TypeScript + Tailwind CSS)
│   ├── src/
│   │   ├── app/
│   │   │   ├── dashboard/        # Dashboard overview & summary KPIs
│   │   │   │   ├── keys/         # Key management & one-time copy modal
│   │   │   │   ├── logs/         # Audit logs viewer & findings inspection
│   │   │   │   ├── playground/   # Interactive split-pane attack playground
│   │   │   │   └── policies/     # Firewall mode toggles & encrypted BYOK
│   │   │   ├── login/            # Tenant sign-in page
│   │   │   ├── register/         # Tenant account creation
│   │   │   └── layout.tsx        # Global dark-mode layout & context providers
│   │   ├── components/           # Sidebar, Header, Breadcrumbs
│   │   ├── context/              # AuthContext & WorkspaceContext
│   │   └── lib/api.ts            # Centralized typed API client
├── handler.py                    # Isolated Mangum AWS Lambda adapter
├── scripts/
│   └── init_db.py                # DynamoDB single-table provisioning script
├── tests/                        # 38 Automated Pytest Suites
│   ├── test_detector.py          # Regex, Luhn, Shannon entropy, injection tests
│   ├── test_auth_and_workspaces.py # Auth, policy, and key lifecycle tests
│   ├── test_bola_idor.py         # Cross-tenant BOLA/IDOR security tests
│   ├── test_proxy.py             # Proxy tests (ALLOW, REDACT, BLOCK, revoked keys)
│   ├── test_dynamodb_repository.py # Direct DynamoDB single-table persistence
│   ├── test_dynamodb_integration.py # Full E2E flow backed by DynamoDB
│   ├── test_e2e_workflows.py     # 4 End-to-end user workflows
│   ├── test_security_and_performance.py # CORS, stack trace leak & <50ms benchmark
│   └── test_init_db.py           # Table provisioning script tests
├── .env.example                  # Environment configuration template
├── pytest.ini                    # Pytest configuration
└── requirements.txt              # Production Python dependencies
```

---

## Local Development Quickstart

### 1. Prerequisites
- **Python:** 3.12 or newer
- **Node.js:** v18 or newer (v20+ recommended)
- **AWS CLI:** (Optional, for deploying to AWS)

### 2. Backend Setup
```bash
# Clone the repository
git clone https://github.com/your-org/gatekeep.git
cd gatekeep

# Install Python dependencies
pip install -r requirements.txt

# Start local FastAPI server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be running at `http://127.0.0.1:8000`. Interactive Swagger documentation is available at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start Next.js development server
npm run dev
```
Frontend Dashboard will be accessible at `http://localhost:3000`.

---

## Running the Automated Test Suite

### Backend Tests (38 Tests)
```bash
# Run complete test suite (unit + DynamoDB integration + E2E workflows + benchmark)
python -m pytest -v
```
All 38 tests run against isolated mock environments (`moto` for DynamoDB, `respx` for upstream HTTP calls) with zero external cloud dependencies.

### Frontend Production Build & Lint
```bash
cd frontend
npm run lint    # 0 errors, 0 warnings
npm run build   # Production static & dynamic page optimization
```

---

## Step-by-Step Deployment Checklist (AWS Free Tier + Vercel)

### Step 1: Provision DynamoDB Table (AWS Free Tier)
Run the automated table provisioning script using your configured AWS credentials:
```bash
python scripts/init_db.py --table-name gatekeep-main --region us-east-1
```
This script provisions:
- Single-Table partition key `PK` (String) and sort key `SK` (String).
- Global Secondary Index `GSI1` (`GSI1PK` + `GSI1SK`) for workspace lookups.
- On-Demand billing (`PAY_PER_REQUEST`).
- Automated 30-day TTL lifecycle cleanup on attribute `ttl`.

### Step 2: Create AWS Lambda IAM Execution Role
Create an IAM Role with basic Lambda execution rights and DynamoDB table access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:BatchWriteItem"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:*:table/gatekeep-main",
        "arn:aws:dynamodb:us-east-1:*:table/gatekeep-main/index/*"
      ]
    }
  ]
}
```

### Step 3: Package & Deploy Backend to AWS Lambda
Because GateKeep isolates the Lambda adapter in `handler.py`, packaging is straightforward:

```bash
# 1. Package dependencies into a deployment zip
mkdir -p build_lambda
pip install -r requirements.txt --target build_lambda/
cp -r app handler.py build_lambda/
cd build_lambda && zip -r ../lambda_artifact.zip . && cd ..

# 2. Create the Lambda function
aws lambda create-function \
  --function-name gatekeep-api \
  --runtime python3.12 \
  --role arn:aws:iam::<YOUR_ACCOUNT_ID>:role/gatekeep-lambda-role \
  --handler handler.handler \
  --zip-file fileb://lambda_artifact.zip \
  --timeout 30 \
  --memory-size 512 \
  --region us-east-1
```

### Step 4: Enable Lambda Function URL ($0/month)
Enable a dedicated HTTPS Function URL with zero API Gateway overhead:
```bash
aws lambda create-function-url-config \
  --function-name gatekeep-api \
  --auth-type NONE \
  --cors '{"AllowOrigins":["*"],"AllowMethods":["*"],"AllowHeaders":["*"],"MaxAge":86400}' \
  --region us-east-1

aws lambda add-permission \
  --function-name gatekeep-api \
  --statement-id FunctionURLAllowPublicAccess \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE \
  --region us-east-1
```
Note the generated URL: `https://<unique-id>.lambda-url.us-east-1.on.aws/`.

### Step 5: Configure Backend Environment Variables
In the AWS Lambda Console, set the following environment variables:
| Variable | Value / Description |
|---|---|
| `REPOSITORY_BACKEND` | `dynamodb` |
| `DYNAMODB_TABLE_NAME` | `gatekeep-main` |
| `AWS_REGION` | `us-east-1` |
| `JWT_SECRET_KEY` | Random 32-byte secret (e.g. `openssl rand -hex 32`) |
| `GATEKEEP_ENCRYPTION_KEY` | 32 url-safe base64 bytes for Fernet BYOK encryption |
| `DEFAULT_UPSTREAM_BASE_URL` | `https://integrate.api.nvidia.com/v1` |

### Step 6: Deploy Frontend to Vercel (Free Tier)
1. Push your repository to GitHub / GitLab.
2. Sign in to [Vercel](https://vercel.com/) and click **Add New Project**.
3. Select your repository and set:
   - **Framework Preset:** Next.js
   - **Root Directory:** `frontend`
4. Add the Environment Variable:
   - `NEXT_PUBLIC_API_URL`: Your AWS Lambda Function URL (e.g. `https://<unique-id>.lambda-url.us-east-1.on.aws`).
5. Click **Deploy**. Vercel will build and serve the dashboard globally with automated SSL and edge caching.

---

## Configuring BYOK Upstream LLM (NVIDIA Nemotron)

1. Sign up for free developer credits at [NVIDIA Build](https://build.nvidia.com/).
2. Generate an API Key (starts with `nvapi-...`).
3. In your GateKeep Dashboard:
   - Navigate to **Firewall Policies** (`/dashboard/policies`).
   - Set **Upstream Base URL** to `https://integrate.api.nvidia.com/v1`.
   - Enter your `nvapi-...` key in the **Upstream API Key (BYOK)** field.
   - Click **Save Policy Configuration**.
4. The key is immediately encrypted at rest using AES-256-GCM / Fernet. Only the sanitized proxy pipeline decrypts it in-memory when forwarding approved requests.

---

## Using the Gateway Proxy (`/v1/chat/completions`)

Once an API Key is generated in the dashboard, client applications and SDKs can use GateKeep as a drop-in replacement for OpenAI endpoints:

```bash
curl -X POST "https://<your-lambda-url>/v1/chat/completions" \
  -H "Authorization: Bearer gw_live_your_gateway_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "nvidia/nemotron-4-340b-instruct",
    "messages": [
      {
        "role": "user",
        "content": "Please charge user alice@company.com with card 4111 1111 1111 1111."
      }
    ]
  }'
```

### Gateway Response with `aegisgate_meta`:
```json
{
  "id": "chatcmpl-9b87f...",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "nvidia/nemotron-4-340b-instruct",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Processed request for user [REDACTED_EMAIL] with payment method [REDACTED_CREDIT_CARD]."
      },
      "finish_reason": "stop"
    }
  ],
  "aegisgate_meta": {
    "action": "REDACT",
    "is_blocked": false,
    "block_reason": null,
    "findings_count": 2,
    "findings": [
      {
        "type": "EMAIL",
        "category": "PII",
        "rule_name": "REGEX_EMAIL",
        "safe_preview": "al***@company.com"
      },
      {
        "type": "CREDIT_CARD",
        "category": "PII",
        "rule_name": "LUHN_CREDIT_CARD",
        "safe_preview": "****-****-****-1111"
      }
    ],
    "inspection_ms": 0.482,
    "upstream_ms": 118.5,
    "total_ms": 118.982,
    "policy_mode": "REDACT"
  }
}
```

---

## Security & Compliance Highlights

- **Zero Plaintext Secrets in Storage:** API keys (`gw_live_...`) are stored only as SHA-256 hashes; upstream LLM keys are encrypted using Fernet.
- **Strict BOLA / IDOR Isolation:** Multi-tenant workspace endpoints verify owner user ID before every database read, write, or query.
- **Safe Previews Only:** Audit logs and client responses mask secrets (`AKIA...`, `****-****-****-1234`) and never log raw unredacted credentials.
- **Inspection Overhead SLA:** Core deterministic firewall engine processes complex multi-threat prompts in **< 1ms** average latency, well below the 50ms production ceiling.
- **Single-Table Design:** Efficiently co-locates users, workspaces, policies, keys, and audit logs within a single DynamoDB table to eliminate relational join overhead and maximize Free Tier resource utilization.
