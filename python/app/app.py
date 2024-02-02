import socketserver

from kubernetes import client, config                      # I imported K8s config modules
from http.server import BaseHTTPRequestHandler


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Catch all incoming GET requests"""
        if self.path == "/healthz":                        # This path will be the landing page for health status of K8s cluster               
            self.healthz()

        elif self.path == "/deployments":                  # This path will be the landing page for health status of K8s deployments
            self.check_deployments_health()
        
        elif self.path == "/pods":                         # This path will be the landing page for health status of pods
            self.check_pods_health()

        elif self.path.startswith("/network-policy"):      # This path would show the Network Policy created to Block/Allow namespaces communicate
            self.handle_network_policy_request()

        else:
            self.send_error(404)


    def healthz(self):
        """Responds with the health status of the application"""
        self.respond(200, "ok")


    ## (THE SOLUTION TO CHECK KUBERNETES DEPLOYMENTS HEALTH) ##

    def check_deployments_health(self):
        """Checks the health of all deployments and responds accordingly"""
     
        try:
            config.load_kube_config()                   # This will load Kubernetes configuration
            v1 = client.AppsV1Api()                     # This will create an instance of the AppsV1Api
            deployments = v1.list_deployment_for_all_namespaces().items  # This will retrieve a list of deployments in all namespaces

        # This will initialize lists for healthy and unhealthy deployments
            healthy_deployments = []
            unhealthy_deployments = []

        # This will iterate through deployments and categorize them as healthy or unhealthy
            for deployment in deployments:
                if deployment.status.replicas == deployment.status.available_replicas:
                    healthy_deployments.append(deployment.metadata.name)
                else:
                    unhealthy_deployments.append(deployment.metadata.name)

        # This will create response content with deployment health information
            response_content = f"Healthy Deployments={len(healthy_deployments)}, Unhealthy Deployments={len(unhealthy_deployments)}\n"
            response_content += f"Healthy Deployments ({len(healthy_deployments)}): {', '.join(healthy_deployments)}\n"
            response_content += f"Unhealthy Deployments ({len(unhealthy_deployments)}): {', '.join(unhealthy_deployments)}"

        # This will make the action respond with appropriate status code based on deployment health
            if unhealthy_deployments:
                self.respond(500, response_content)
            else:
                self.respond(200, response_content)

        # This wil make the action respond with 500 status code and error message if an exception occurs
        except Exception as e:
            self.respond(500, f"Error checking deployments health: {str(e)}")



    ## (THE SOLUTION TO CHECK PODS HEALTH) ##

    def check_pods_health(self):
        """Checks the health of all pods and responds accordingly"""
        
        try:
            config.load_kube_config()                            # This will load Kubernetes configuration
            v1 = client.CoreV1Api()                              # This will create an instance of the AppsV1Api
            pods = v1.list_pod_for_all_namespaces().items        # This will retrieve a list of pods in all namespaces

        # This will initialize lists for healthy and unhealthy pods
            healthy_pods = []
            unhealthy_pods = []

        # This will iterate through pods and categorize them as healthy or unhealthy
            for pod in pods:
                if pod.status.phase == "Running":
                    healthy_pods.append(pod.metadata.name)
                else:
                    unhealthy_pods.append(pod.metadata.name)

        # This will create response content with pod health information
            response_content = f"Healthy Pods={len(healthy_pods)}, Unhealthy Pods={len(unhealthy_pods)}\n"
            response_content += f"Healthy Pods ({len(healthy_pods)}): {', '.join(healthy_pods)}\n"
            response_content += f"Unhealthy Pods ({len(unhealthy_pods)}): {', '.join(unhealthy_pods)}"

        # This will make the action respond with appropriate status code based on pod health
            if unhealthy_pods:
                self.respond(500, response_content)
            else:
                self.respond(200, response_content)

        # This wil make the action respond with 500 status code and error message if an exception occurs
        except Exception as e:
            self.respond(500, f"Error checking pods health: {str(e)}")


    ## (THE SOLUTION TO HANDLE NETWORK POLICY REQUESTS) ##
            
    def handle_network_policy_request(self):
        """Handle requests related to network policies"""
        try:

        # This will split the path into segments
            path_segments = self.path.split('/')
            print(path_segments)

        # This will check if the number of path segments is valid
            if len(path_segments) == 5:
                operation = path_segments[2]
                source_namespace = path_segments[3]


                config.load_kube_config()                                               # This will load Kubernetes configuration
                v1 = client.CoreV1Api()                                                 # This will create an instance of the CoreV1Api
                namespaces = [ns.metadata.name for ns in v1.list_namespace().items]     # This will retrieve a list of namespaces

        # This will check if the source namespace exists
                if source_namespace in namespaces:
                    if operation == "block" or operation == "allow":
                        target_namespace = path_segments[4]
                     
                      # Then, this will create a network policy based on the operation
                        self.create_network_policy(source_namespace, target_namespace, block=(operation == "block"))
                    else:
                        self.send_error(400, "Invalid operation. Use 'block' or 'allow'.")
                else:
                    self.send_error(404, f"Namespace {source_namespace} not found.")
            else:
                self.send_error(400, "Invalid number of path segments.")
        
        # This wil make the action respond with 500 status code and error message if an exception occurs
        except Exception as e:
            self.respond(500, f"Error handling network policy request: {str(e)}")

    
    def create_network_policy(self, source_namespace, target_namespace, block=True):
        """Create a network policy to block or allow communication between namespaces"""
        try:

        # This will create an instance of the NetworkingV1Api
            v1 = client.NetworkingV1Api()

        # This will define the name and action of the network policy
            policy_name = f"{source_namespace}-{target_namespace}-policy"
            policy_action = "block" if block else "allow"


        # This will create the network policy based on the action
            if block:
                policy = client.V1NetworkPolicy(
                    api_version="networking.k8s.io/v1",
                    kind="NetworkPolicy",
                    metadata=client.V1ObjectMeta(name=policy_name, namespace=source_namespace),
                    spec=client.V1NetworkPolicySpec(
                        pod_selector=client.V1LabelSelector(match_labels={}),
                        ingress=[],
                        egress=[
                            client.V1NetworkPolicyEgressRule(
                                to=[
                                    client.V1NetworkPolicyPeer(
                                        namespace_selector=client.V1LabelSelector(
                                            match_labels={"app": target_namespace}
                                        )
                                    )
                                ]
                            )
                        ],
                    ),
                )
            else:
                policy = client.V1NetworkPolicy(
                    api_version="networking.k8s.io/v1",
                    kind="NetworkPolicy",
                    metadata=client.V1ObjectMeta(name=policy_name, namespace=source_namespace),
                    spec=client.V1NetworkPolicySpec(
                        pod_selector=client.V1LabelSelector(match_labels={}),
                        ingress=[
                            client.V1NetworkPolicyIngressRule(
                                from_=[
                                    client.V1NetworkPolicyPeer(
                                        namespace_selector=client.V1LabelSelector(
                                            match_labels={"app": target_namespace}
                                        )
                                    )
                                ]
                            )
                        ],
                        egress=[],
                    ),
                )


        # This will create the network policy
            v1.create_namespaced_network_policy(source_namespace, policy)
            self.respond(200, f"NetworkPolicy {policy_action} communication between {source_namespace} and {target_namespace} created.")
        
        # This wil make the action respond with 500 status code and error message if an exception occurs
        except Exception as e:
            self.respond(500, f"Error creating network policy: {str(e)}")








    def respond(self, status: int, content: str):
        """Writes content and status code to the response socket"""
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        self.wfile.write(bytes(content, "UTF-8"))


def get_kubernetes_version(api_client: client.ApiClient) -> str:
    """
    Returns a string GitVersion of the Kubernetes server defined by the api_client.

    If it can't connect an underlying exception will be thrown.
    """
    version = client.VersionApi(api_client).get_code()
    return version.git_version


def start_server(address):
    """
    Launches an HTTP server with handlers defined by AppHandler class and blocks until it's terminated.

    Expects an address in the format of `host:port` to bind to.

    Throws an underlying exception in case of error.
    """
    try:
        host, port = address.split(":")
    except ValueError:
        print("invalid server address format")
        return

    with socketserver.TCPServer((host, int(port)), AppHandler) as httpd:
        print("Server listening on {}".format(address))
        httpd.serve_forever()
