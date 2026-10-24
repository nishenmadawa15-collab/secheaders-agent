# Deploying the SecHeaders scan Lambda

This Lambda is **self-contained and dependency-free**: it uses only the Python
standard library, so the deployment package is just `lambda_function.py` and
`header_checks.py`. No `pip install`, no layers.

## (a) Deploy with the AWS SAM CLI (recommended)

From inside this `lambda/` directory:

```bash
sam build
sam deploy --guided
```

`--guided` asks for a stack name and region once and saves them to
`samconfig.toml`; later deploys are just `sam build && sam deploy`. The function
is named `secheaders-scan` (see `template.yaml`).

## (b) Manual zip + console upload (no SAM)

```bash
cd lambda
zip secheaders-scan.zip lambda_function.py header_checks.py
```

Then in the AWS Console: **Lambda -> Create function -> Author from scratch**,
Runtime **Python 3.12**. After creating it, **Upload from -> .zip file** and pick
`secheaders-scan.zip`. Set **Handler** to `lambda_function.lambda_handler`, and
under **Configuration -> General**: Timeout 15s, Memory 256 MB.

## (c) IAM notes

- **Lambda execution role**: needs only basic Lambda logging
  (`AWSLambdaBasicExecutionRole` - CloudWatch Logs). It makes no AWS API calls.
- **The local agent that invokes it** (your machine running `agent.py` with
  `tool_lambda.py`): its IAM principal needs `lambda:InvokeFunction` on the
  function's ARN, e.g.
  ```json
  {"Effect": "Allow", "Action": "lambda:InvokeFunction",
   "Resource": "arn:aws:lambda:us-east-1:*:function:secheaders-scan"}
  ```

## (d) Test it

Direct invoke from the CLI:

```bash
aws lambda invoke --function-name secheaders-scan \
  --payload '{"url":"github.com"}' \
  --cli-binary-format raw-in-base64-out \
  out.json
cat out.json
```

`out.json` will contain `{"grade", "score", "report", "url"}` (or `{"error":...}`).
