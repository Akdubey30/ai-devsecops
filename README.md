# AI-Enhanced DevSecOps Pipeline

## Project Overview

This project is an AI-enhanced DevSecOps pipeline that integrates security checks and AI-based vulnerability prediction into the software development lifecycle.

In a traditional DevOps pipeline, code is built, tested, and deployed automatically. However, security checks are often performed late in the development process. This project improves the process by adding security analysis and AI-based decision-making before deployment. This is just a demo

The main goal of this project is to check whether the code is safe enough to be deployed.

---

## Problem Statement

Modern software applications are frequently updated through CI/CD pipelines. While this improves development speed, it can also increase the risk of insecure code reaching production.

Common issues include:

- Hardcoded passwords
- SQL injection
- Command injection
- Vulnerable dependencies
- Unsafe coding practices
- Lack of automated security review

This project solves this problem by integrating security scanning and AI-based vulnerability detection inside the DevSecOps pipeline.

---

## Objective

The main objectives of this project are:

- To automate security checks using a CI/CD pipeline
- To detect vulnerabilities before deployment
- To use AI for code risk prediction
- To generate security reports
- To provide a deployment decision based on risk level
- To improve software security in the early development stage

---

## Technologies Used

- Python
- Streamlit
- GitHub Actions
- Bandit
- Semgrep
- pip-audit
- Machine Learning
- CodeBERT concept for code representation
- Random Forest classifier
- Git and GitHub

---

## System Workflow

The workflow of the project is:

```text
Developer pushes code to GitHub
        ↓
GitHub Actions pipeline starts automatically
        ↓
Dependencies are installed
        ↓
Static security analysis is performed
        ↓
Dependency vulnerability scan is performed
        ↓
AI model analyses the code
        ↓
Security report is generated
        ↓
Deployment decision is displayed