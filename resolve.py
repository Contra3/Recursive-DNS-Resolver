"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 19 March 2018
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

CACHE_SYSTEM = {}

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}

    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    if response is not None:
        for answers in response.answer:
            for answer in answers:
                cnames.append({"name": answer, "alias": name})

    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []

    if response is not None:
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})

    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []

    if response is not None:
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append({"name": aaaa_name, "address": str(answer)})

    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    if response is not None:
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response

def recursive_dns_lookup(target_name, qtype, root_servers_list): 
    """
    Helper function that does the recursive DNS resolving
    """

    # Base case
    if not root_servers_list:
        return None

    # Create dns query based on the target_name (website)
    # and qtype (queue type: CNAME, A, AAAA, or MX)
    dns_query = dns.message.make_query(target_name, qtype)

    for server in root_servers_list:
        # Doing a try catch to check if the dns server times out,
        # if it does then we continue and try another server
        try:
            query_response = dns.query.udp(dns_query, server, 3)
        except dns.exception.Timeout:
            continue
        # If there's an answer in the response
        if query_response.answer:
            # Search through the response.answer for possible answers
            for response_answers in query_response.answer:
                #print("response_answers: ", response_answers)
                for response_answer in response_answers:
                    #print("Response_answer", response_answer)
                    target_name = str(response_answer)[:-1] # Removes the period at the end
                    #print("Target_name", target_name)
                    # If we don't get the reponse we're after then
                    # continue searching through the root_servers
                    if response_answer.rdtype != qtype:
                        if response_answer.rdtype == 5:
                            return recursive_dns_lookup(target_name, qtype, ROOT_SERVERS)
                    else:
                        # Return the answer we wanted
                        return query_response
        else: # If there isn't an answer in the response then we check additional

            # If we do have something in additional then get the stuff inside
            if query_response.additional:
                ip_addresses = []
                for response_additional in query_response.additional:
                    #print("response_additional: ", response_additional)
                    # Convert to string then send to function for parsing the address out
                    response_additional_str = str(response_additional)

                    #print("function get_address resp:", resp)
                    resp_elements = response_additional_str.split()
                    #print("function get_address resp_elements:", resp_elements)
                    ip_address = []
                    for resp_element in resp_elements:
                        #print("function get_address resp_element:", resp_element)
                        if resp_element != 'A':
                            continue
                        else:
                            #print("function get_address resp_element = A:", resp_element)
                            #print("function get_address address:", resp_elements[-1])
                            ip_address.append(resp_elements[-1])
                    ip_addresses += ip_address

                return recursive_dns_lookup(target_name, qtype, ip_addresses)


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """

    # Using recursive_dns_lookup as a helper function we
    # send in the information required to get the response we want
    responses = recursive_dns_lookup(target_name, qtype, ROOT_SERVERS)
    return responses


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        ##print("Domain name: ", a_domain_name)
        ##print("Cache System: ", CACHE_SYSTEM)
        if a_domain_name in CACHE_SYSTEM:
            print_results(CACHE_SYSTEM[a_domain_name])
        else:
            # Saves the domain name in a cache system and if it's searched
            # again then it won't requery and just print it out from the
            # cache system
            CACHE_SYSTEM[a_domain_name] = collect_results(a_domain_name)
            print_results(CACHE_SYSTEM[a_domain_name])

if __name__ == "__main__":
    main()
