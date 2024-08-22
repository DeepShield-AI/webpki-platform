
'''
    This file is used to build data structures for large domain set lookup
    e.g. Check if domain lies in Top-1M or Top-10M set

    Two parts for this:
        1. hash set(): use set() for basic checking, if matched, then its good, return true
            For wildcard names, we replace the last layer of the domain to *, and then store into set()
            e.g. store both www.example.com and *.example.com
        2. Wildcard Dictionary: use dictionary to connect wildcard domains and fix domains
            e.g. {
                "*.example.com" : [ www.example.com. mails.example.com ]
            }
            We can add the wildcard certificates to both groups with this
'''

import os
import csv

class DomainLookup():

    def __init__(self) -> None:

        self.domain_set = set()
        self.wildcard_dict = {}
        
        with open(os.path.join(os.path.dirname(__file__), r"../data/top-1m.csv"), 'r') as file:
            csv_reader = csv.reader(file)

            for row in csv_reader:

                wildcard_domain = self.replace_subdomain_with_wildcard(row[1])
                self.domain_set.add(row[1])
                self.domain_set.add(wildcard_domain)

                if wildcard_domain not in self.wildcard_dict:
                    self.wildcard_dict[wildcard_domain] = []
                self.wildcard_dict[wildcard_domain].append(row[1])

    def replace_subdomain_with_wildcard(self, domain):

        parts = domain.split('.')
        if len(parts) >= 2:
            parts[0] = '*'
        
        wildcard_domain = '.'.join(parts)
        return wildcard_domain
    
    def lookup(self, target_domain : str):

        is_wildcard = target_domain.startswith("*.")
        is_hit = target_domain in self.domain_set

        if is_hit and is_wildcard:
            return self.wildcard_dict[target_domain]
        elif is_hit and (not is_wildcard):
            return target_domain
        else:
            return None


# @deprecated
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_domain = False

# @deprecated
class DomainTrie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, domain):
        node = self.root
        labels = domain.split('.')[::-1]  # 从 TLD 开始
        for label in labels:
            if label not in node.children:
                node.children[label] = TrieNode()
            node = node.children[label]
        node.is_end_of_domain = True

    def search(self, domain):
        node = self.root
        labels = domain.split('.')[::-1]  # 从 TLD 开始
        for label in labels:
            if label in node.children:
                node = node.children[label]
            elif '*' in node.children:  # 匹配通配符
                node = node.children['*']
            else:
                return False
        return node.is_end_of_domain
