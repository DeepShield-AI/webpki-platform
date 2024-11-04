
'''
    Algorithm implementation for SAN templates

    Input:
        Target Domain
        Subject List
    Output:
        Control Vector
        Relation Vector

    These two vectors both contributes to the SAN template
'''

EMPTY = 0
MARK = 1
COMPUTE = 2

class TrieNode:
    def __init__(self, level : int, value : str):
        self.value = value
        self.level = level
        self.children = {}
        # "com" : Node()
        self.state = EMPTY
        self.is_end_of_domain = False


class DomainTrieTree:
    def __init__(self):
        self.root = TrieNode(0, "****")


    def print_node(self, node : TrieNode):
        print(list(node.children.keys()))
        for print_node in node.children.values():
            self.print_node(print_node)


    def print(self):
        self.print_node(self.root)


    def insert(self, domain : str):
        node = self.root
        labels = domain.split('.')[::-1]  # reverse
        for label in labels:
            if label not in node.children:
                node.children[label] = TrieNode(node.level + 1, label)
            node = node.children[label]
        node.is_end_of_domain = True


    def search_label_on_nodes(self, current_node : TrieNode, label : str):
        find_nodes = []
        if label in current_node.children:
            if current_node.children[label].state == EMPTY:
                find_nodes.append(current_node.children[label])

        for child_node in current_node.children.values():
            find_nodes += self.search_label_on_nodes(child_node, label)

        return find_nodes


    def search_label(self, label : str):
        current_node = self.root
        return self.search_label_on_nodes(current_node, label)
    

    def build_trie_tree(self, san_list : list):
        for domain in san_list:
            self.insert(domain)


    # www, a, com
    def search_and_mark_domain(self, domain_split : list):
        final_nodes = []
        find_nodes_root = self.search_label(domain_split[0])
        # print(find_nodes_root[0].is_end_of_domain)

        for root_node in find_nodes_root:
            root_node_match = True

            # find path
            node = root_node
            path = domain_split[1:]
            for i in range(len(path)):
                label = path[i]
                if label in node.children:
                    node = node.children[label]
                else:
                    # check * at the end
                    if (i == len(path) - 1) and ("*" in node.children):
                        pass
                    else:
                        root_node_match = False
                        break

            if root_node_match:
                final_nodes.append(root_node)
        return final_nodes


    def compute_control_vector(self, fqdn : str) -> list:

        return_vector = []
        fqdn_split = fqdn.split('.')[::-1]
        # e.g. [com, a, www]

        for i in range(len(fqdn_split) - 1):
            domain_split = fqdn_split[i:]
            # print(domain_split)
            # domain_split.reverse()
            # domain_split += ['*'] * i
            find_nodes_root = self.search_and_mark_domain(domain_split)
            # print(find_nodes_root)

            sub_vector = []
            for root_node in find_nodes_root:
                # compute the sub-vector
                level_root = root_node.level
                level_top = level_root + len(domain_split) - 1
                sub_vector.append((level_root, level_top))
                # print(sub_vector)

                level_score_tuple = []
                node = root_node
                node.state = MARK
                level_score_tuple.append(self.compute_node_score(node))

                # check *
                if "*" in node.children:
                    node.children["*"].state = MARK
                    level_score_tuple.append("*")

                path = domain_split[1:]
                for i in range(len(path)):

                    label = path[i]
                    node = node.children[label]
                    node.state = MARK

                    if len(level_score_tuple) != (i+2):
                        level_score_tuple.append(self.compute_node_score(node))
                    # print(f"{node.value} : {self.compute_node_score(node)}")
                    
                    # check *
                    if "*" in node.children:
                        node.children["*"].state = MARK
                        level_score_tuple.append("*")

                # TODO: trim the length
                sub_vector.append(level_score_tuple)
            return_vector.append(sub_vector)
        return return_vector

    def compute_node_score(self, node):
        # print(node.value)

        if "*" == node.value:
            return "*"

        if node.is_end_of_domain:
            return 1

        return 0


    def get_max_unmarked_subtrees(self, root : TrieNode):
        roots = []
        if self.check_unmarked_sub_tree(root):
            return [root]

        # self is not fully unmarked
        for node in root.children.values():
            roots += self.get_max_unmarked_subtrees(node)
        return roots


    def check_unmarked_sub_tree(self, root : TrieNode) -> bool:
        if root.state == MARK:
            return False
        
        if not root.children:
            return True

        for node in root.children.values():
            if not self.check_unmarked_sub_tree(node):
                return False
        return True



    def compute_relation_vector(self, fqdn : str) -> list:
        '''
            Make sure this function is called after the compute_control_vector()!!!
        '''
        return_vector = []
        roots = self.get_max_unmarked_subtrees(self.root)

        # TODO: remove subdomain of the target domains
        for root in roots:
            return_vector.append(root.level)
        return sorted(return_vector)


    def compute_san_template(self, fqdn : str) -> tuple[list, list]:
        return (self.compute_control_vector(fqdn), self.compute_relation_vector(fqdn))


sans = ["www.a.com", "a.com", "b.org", "*.a.com", "b.com"]
tree = DomainTrieTree()
tree.build_trie_tree(sans)
# tree.print()
print(tree.compute_control_vector(sans[3]))
print(tree.compute_relation_vector(sans[3]))

