#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul  4 16:25:01 2023

@author: nicolas
"""

import requests
import streamlit as st
import whois
import dns.resolver

def get_whois_record(domain):
    try:
        record = whois.whois(domain)
        return record
    except Exception as e:
        return str(e)

def check_robots_txt(domain):
    try:
        response = requests.get(f"http://{domain}/robots.txt")
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False


def check_ads_txt(domain):
    try:
        response = requests.get(f"http://{domain}/ads.txt")
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_address = answers[0].address
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(record.exchange) for record in mx_records]
        return ip_address, mx_records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, None


def main():
    st.title("WHOIS Record and Robots.txt Checker")

    # User input for domain
    domain = st.text_input("Enter a website URL (e.g., example.com):")
    
    col1, col2, col3 = st.columns(3)
    col4, col5, col6 = st.columns(3)

    if col1.button("Get WHOIS Record"):
        if domain:
            whois_record = get_whois_record(domain)
            if isinstance(whois_record, str):
                st.error(f"Error retrieving WHOIS record: {whois_record}")
            else:
                st.success("WHOIS record retrieved successfully!")
                st.json(whois_record)
        else:
            st.warning("Please enter a valid domain name.")

    if col2.button("Check Robots.txt"):
        if domain:
            has_robots_txt = check_robots_txt(domain)
            if has_robots_txt:
                st.success("Robots.txt file found!")
            else:
                st.warning("Robots.txt file not found.")
        else:
            st.warning("Please enter a valid domain name.")


    if col3.button("Check ads.txt"):
        if domain:
            has_robots_txt = check_robots_txt(domain)
            if has_robots_txt:
                st.success("ads.txt file found!")
            else:
                st.warning("ads.txt file not found.")
        else:
            st.warning("Please enter a valid domain name.")
            

    if col4.button("Check MX DNS records"):
        ip_address, mx_records = get_dns_records(domain)
        if ip_address is not None:
            st.success(f"IP Address: {ip_address}")
        else:
            st.error("Invalid domain name or DNS record not found.")

        if mx_records:
            st.success("MX Records:")
            for record in mx_records:
                st.write(record)
        else:
            st.error("No MX records found for the domain.")

            

    if col6.button("Full check"):
        ip_address, mx_records = get_dns_records(domain)
        if ip_address is not None:
            st.success(f"IP Address: {ip_address}")
        else:
            st.error("Invalid domain name or DNS record not found.")

        if mx_records:
            st.success("MX Records:")
            for record in mx_records:
                st.write(record)
        else:
            st.error("No MX records found for the domain.")


if __name__ == "__main__":
    main()