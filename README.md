# tbrr - Thread Border Router Router

**tbrr** is a hacky sidecar container designed to complement [python-matter-server](https://github.com/home-assistant-libs/python-matter-server) when running in Kubernetes. 
It helps ensure routing towards Thread devices in cases where router advertisements cannot reach the Matter server pod for various reasons.

**tbrr** queries each specified Thread Border Router for its routable devices and adds their prefixes as routes in the pod.

Tested using Aqara M3 and a Google Nest hubs as thread routers. Matter device setup was done on each hub and "shared" with the `python-matter-server`.

## Usage

To run `tbrr` directly:

```bash
tbrr <thread border router IP 1> [<thread border router IP 2> ...]
```
Note: tbrr requires NET_ADMIN and NET_RAW capabilities.

### Example

```bash
COMMIT='true' INTERFACE_NAME='eth0' tbrr fe80::2bc3:4dff:fe6e:1234 fe80::2bc3:4dff:fe6e:5678
```

## K8s Sidecar

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: matter-server
  labels:
    app: matter-server
spec:
  selector:
    matchLabels:
      app: matter-server
  replicas: 1
  template:
    metadata:
      labels:
        app: matter-server
    spec:
      hostNetwork: true
      containers:
      - name: tbrr
        image: ghcr.io/tiborv/tbrr:latest
        securityContext:
          runAsUser: 0
          capabilities:
            drop: ["ALL"]
            add: ["NET_ADMIN", "NET_RAW"]
        env:
          - name: INTERFACE_IPS
            valueFrom:
              fieldRef:
                fieldPath: status.podIPs # tbrr will ignore non-IPv6s
          - name: COMMIT
            value: "true"
        args:
          - 'fe80::1ac2:3cff:fe4d:76ed'
      - name: matter-server
        image: ghcr.io/home-assistant-libs/python-matter-server:stable
        args:
          - '--storage-path'
          - /data
        volumeMounts:
          - name: data
            mountPath: /data
        ports:
        - containerPort: 5580
      volumes:
      - name: data
        emptyDir: {}
```

## Environment Variables

The following environment variables can be used to configure `tbrr`:

- **COMMIT**  
  If set to true, commits the route changes. Example:  
  ```bash
  COMMIT="true"
  ```
- **INTERFACE_NAME**  
  Select the network interface to use by its name. Example:  
  ```bash
  INTERFACE_NAME="eth0"
  ```
- **INTERFACE_IPS**  
  Select the interface to use by specifying one of the IPv6 addresses assigned to the interface. Example:  
  ```bash
  INTERFACE_IPS="fe80::1ac2:3cff:fe4d:76ed"
  ```
- **SYNC_INTERVAL**  
  Set the sync interval timeout between each sync run. Example:  
  ```bash
  SYNC_INTERVAL="30s"
  ```