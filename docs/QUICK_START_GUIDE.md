# dLNk dLNk Framework - Quick Start Guide

**Version:** 3.0 (Final)

Welcome to the dLNk dLNk Framework! This guide will get you up and running in minutes, allowing you to launch your first automated penetration test.

---

### **Step 1: Install and Launch using Docker**

This is the fastest way to get started. Make sure you have Docker and Docker Compose installed.

1.  **Unzip the package:**
    ```bash
    unzip dlnk_dlnk_framework_v3_final.zip
    cd dlnk_dlnk
    ```

2.  **Build and run the containers:**
    ```bash
    docker-compose up --build -d
    ```

---

### **Step 2: Activate Your License**

You need to activate the framework with your license key before you can use it. Run the following command, replacing `<YOUR_LICENSE_KEY>` with the key you were provided.

```bash
docker-compose exec app dlnk-dlnk license activate <YOUR_LICENSE_KEY>
```

To verify, check the license status:

```bash
docker-compose exec app dlnk-dlnk license status
```

---

### **Step 3: Launch Your First Attack (Full Auto)**

The framework is now ready for action. The easiest way to see it in action is to use the `full-auto` attack mode, which automates the entire process from scanning to exploitation.

For this example, we will use a publicly available test site, `localhost:8000`.

**Execute the command:**

```bash
docker-compose exec app dlnk-dlnk attack full-auto --target localhost:8000
```

---

### **Step 4: Monitor the Attack**

Once the attack is launched, you can monitor its progress in real-time in two ways:

1.  **Via the CLI Logs:**
    Watch the live log output from the container.
    ```bash
    docker-compose logs -f app
    ```

2.  **Via the Web Dashboard:**
    Open your web browser and navigate to `localhost:8000`. The dashboard provides a live stream of logs and a high-level overview of the operation.

---

### **What's Next?**

Congratulations! You have successfully launched your first automated attack with the dLNk dLNk Framework.

To explore the full capabilities of the framework, please refer to the following documents:

-   **`THAI_USER_GUIDE.md`**: The complete user manual with in-depth explanations of all features and agents.
-   **`API_REFERENCE.md`**: For integrating the framework with other systems.
-   **`CLI_REFERENCE.md`**: A detailed guide to all available CLI commands and options.

