#!/usr/bin/env python3
# coding: utf-8
# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# Escalator method script: TippingPoint SMS upload.

from __future__ import print_function
import lxml.etree as ETree
import string
import sys
from lxml.etree import fromstring, tostring
from io import open

#
# Test if a byte is the leading byte of a UTF-8 character,
#  i.e. it does not match the bit pattern 10xxxxxx.
#
def utf8_leading_byte(b):
    return (b & 0xC0) != 0x80

#
# Truncate a string to a given number of UTF-8 bytes
#
def truncate_utf8 (input_str, max_bytes):
  utf8 = input_str.encode('utf8')
  ellipsis = '[...]'
  if (max_bytes <= len(ellipsis.encode('utf8'))):
    ellipsis = ''

  if len(utf8) <= max_bytes:
    return utf8.decode('utf-8')
  i = max_bytes - len(ellipsis.encode('utf8'));
  while i > 0 and not utf8_leading_byte(utf8[i]):
      i -= 1
  return utf8[:i].decode('utf-8') + ellipsis

#
# Convert to a CSV data string
#
def to_csv_data (input_obj, max_bytes):
  input_str = str(input_obj);
  quotes_replaced = input_str.replace (u'\"', u'\'\'')
  truncated = truncate_utf8 (quotes_replaced, max_bytes)
  return u'\"' + truncated + u'\"';

#
# Print an array as CSV
#
def write_csv (array, out_file):
  separator = u', '
  joined = separator.join (array)
  print (joined, file = out_file)
#
# Convert a CVSS value to a "Tipping Point" severity,
#  based on CVSS v3.0 ratings
#
def cvss_to_tp_severity (cvss):
  cvss = float(cvss)
  if (cvss >= 9.0):
    return "Critical"
  elif (cvss >= 7.0):
    return "High"
  elif (cvss >= 4.0):
    return "Medium"
  elif (cvss > 0.0):
    return "Low"
  else:
    return None

#
# Collect host data from an XML element tree
#
def get_hosts (xml_tree):
  host_elems = xml_tree.xpath ('host');
  hosts = {};

  for host_elem in host_elems:
    ip = host_elem.find('ip').text
    host = { 'ip': ip, 'MAC': '', 'hostname': '' }

    for detail_elem in host_elem.findall('detail'):
      detail_name = detail_elem.find('name').text;
      detail_value = detail_elem.find('value').text;
      if (detail_name == 'hostname'):
        host['hostname'] = detail_value;
      elif (detail_name == 'MAC'):
        host['MAC'] = detail_value;

    hosts[ip] = host;
  return hosts;

#
# Convert an XML element tree to an TippingPoint CSV file
#
def convert (xml_tree, out_file):
  hosts = get_hosts (xml_tree);

  write_csv (('IP_ADDRESS',       # Required data
              'CVE_IDS',
              'SEVERITY',
              'MAC_ADDRESS',      # Optional asset data
              'HOST_NAME',
              'PORT',
              'VULNERABILITY_ID', # Optional vulnerability data
              'VULNERABILITY_TITLE',
              'CVSS_SCORE',
              'DESCRIPTION',
              'SOLUTION'),
              out_file)

  result_elems = xml_tree.xpath ('results/result');
  for result_elem in result_elems:
    severity_elem = result_elem.find ('severity');
    cvss = None;
    if (severity_elem is not None):
      cvss = severity_elem.text
    if (not (float (cvss) > 0.0)):
      continue;
    ip = result_elem.find ('host').text
    description = result_elem.find ('description').text

    nvt_elem = result_elem.find ('nvt')
    nvt_cve = nvt_elem.find ('cve').text;
    if (nvt_cve == 'NOCVE' or nvt_cve == '' or nvt_cve is None):
      continue;

    nvt_oid = nvt_elem.attrib['oid']
    nvt_name = nvt_elem.find ('name').text;
    tp_severity = cvss_to_tp_severity (cvss);

    port = result_elem.find ('port').text
    port_number = port.split('/')[0];
    if (port_number.isdigit()):
      port_number = int (port_number)
    else:
      port_number = ''

    tags_array = nvt_elem.find ('tags').text.split('|')
    tags = {}
    for tag in tags_array:
      tag_split = tag.split ('=', 1)
      tags[tag_split[0]] = tag_split[1]

    solution = ''
    if ('solution' in tags):
      solution = tags['solution']

    hostname = ''
    mac = ''
    if (ip in hosts):
      if "hostname" in hosts[ip]:
        hostname = hosts[ip]["hostname"]
      if "MAC" in hosts[ip]:
        mac = hosts[ip]["hostname"]

    write_csv ((
                to_csv_data (ip, 50),
                to_csv_data (nvt_cve, 2000),
                to_csv_data (tp_severity, 10),
                to_csv_data (hostname, 100),
                to_csv_data (mac, 250),
                to_csv_data (port_number, 5),
                to_csv_data (nvt_oid, 150),
                to_csv_data (nvt_name, 250),
                to_csv_data (cvss, 5),
                to_csv_data (description, 5000),
                to_csv_data (solution, 2000)
               ),
               out_file)

  return

#
# Main startup function
#
def main ():
  if (len(sys.argv) != 3):
    print ("usage: %s <xml_filename> <output_filename>" % sys.argv[0], file=sys.stderr);
    sys.exit(1);
  xml_filename = sys.argv[1]
  output_filename = sys.argv[2]

  xml_tree = ETree.parse (xml_filename)
  out_file = open (output_filename, 'w', encoding="utf-8")
  convert (xml_tree, out_file);
  out_file.close ();

  return

if __name__ == '__main__':
  main()
