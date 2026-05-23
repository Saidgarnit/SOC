# Setting Up Slack Integration for SSH Alerts

## Step 1: Create Slack Workspace/Channel
1. Go to https://slack.com
2. Create workspace or use existing one
3. Create channel: #soc-alerts

## Step 2: Create Incoming Webhook
1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. App name: "SOC Lab Alerts"
4. Choose workspace
5. Go to "Incoming Webhooks" → Enable
6. Click "Add New Webhook to Workspace"
7. Select #soc-alerts channel
8. Copy the Webhook URL (looks like: https://hooks.slack.com/services/YOUR/WEBHOOK/URL)

## Step 3: Configure ElastAlert with Webhook
Update the webhook URL in elastalert configuration and restart container

## Step 4: Test Alert
Run SSH brute-force attack and check Slack channel for alerts
