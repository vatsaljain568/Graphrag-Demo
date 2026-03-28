import networkx as nx
import pickle
import matplotlib.pyplot as plt


# Graph
G = nx.DiGraph()

G.add_nodes_from([
    ("blueocean-plugin", {"type": "Plugin"}),
    ("pipeline-plugin", {"type": "Plugin"}),
    ("credentials-plugin", {"type": "Plugin", "version": "3.0"}),
    ("git-plugin", {"type": "Plugin", "version": "4.0"}),
    ("CVE-2024-1234", {"type": "CVE", "severity": "HIGH"}),
    ("v4.1", {"type": "Version"}),
])

G.add_edges_from([
    ("blueocean-plugin", "pipeline-plugin", {"relation": "DEPENDS_ON"}),
    ("pipeline-plugin", "credentials-plugin", {"relation": "CONFLICTS_WITH"}),
    ("credentials-plugin", "CVE-2024-1234", {"relation": "HAS_CVE"}),
    ("git-plugin", "CVE-2024-1234", {"relation": "HAS_CVE"}),
    ("CVE-2024-1234", "v4.1", {"relation": "FIXED_IN"}),
])

# Serialize
with open("jenkins_graph.pkl", "wb") as f:
    pickle.dump(G, f)

# Load at query time
with open("jenkins_graph.pkl", "rb") as f:
    G = pickle.load(f)

# Confidence-based query router
def route_query(query: str) -> str:
    relational_keywords = ["conflict", "depend", "CVE", "security", "version"]
    if any(kw.lower() in query.lower() for kw in relational_keywords):
        return "graph"
    return "vector"

# Multi-hop traversal
def graph_query(G, plugin_name, hops=2):
    if plugin_name not in G:
        return []
    paths = nx.single_source_shortest_path(G, plugin_name, cutoff=hops)
    results = []
    for target, path in paths.items():
        if target != plugin_name:
            edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
            chain = " → ".join([
                f"{u} --[{G[u][v]['relation']}]--> {v}"
                for u, v in edges
            ])
            results.append(chain)
    return results


# Visual
def visualize_graph(G):
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="skyblue", font_weight="bold", node_size=1500, font_size=10)
    edge_labels = nx.get_edge_attributes(G, "relation")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.show()


queries = [
    "Which plugins conflict with BlueOcean?",
    "What CVEs affect blueocean-plugin?",
    "How do I install a plugin?",
]

for query in queries:
    route = route_query(query)
    print(f"\nQuery: {query}")
    print(f"Router Decision: {route.upper()} path")
    if route == "graph":
        results = graph_query(G, "blueocean-plugin")
        for r in results:
            print(f"  {r}")
    else:
        print(" Routed to FAISS vector search")

visualize_graph(G)
