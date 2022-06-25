###############################################################################
# OpenVAS Vulnerability Test
# $Id: netop_infopublic.nasl 10228 2018-06-15 16:18:37Z cfischer $
#
# NetOp products information disclosure
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)
# Jakob Bohm of Danware (http://www.danware.dk)
#
# Copyright:
# Copyright (C) 2004 Corsaire Limited and Danware Data A/S
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15767");
  script_version("$Revision: 10228 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 18:18:37 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11710);
  script_cve_id("CVE-2004-0950");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("NetOp products information disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright('This NASL script is Copyright 2004 Corsaire Limited and Danware Data A/S.');
  script_family("General");
  script_dependencies("netop_detect_udp.nasl", "netop_detect_tcp.nasl");
  script_mandatory_keys("NetOp/allbanners");

  script_tag(name:"summary", value:"This script simply displays the basic name and address information provided
  by NetOp products for easy network browsing and reminds admins to turn off that information if they don't want
  it to be visible.

  The script also provides program-specific instructions for doing so depending on the actual product detected");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("netop.inc");

function named_items( nam, typ ) {

  local_var v1;
  v1 = netop_banner_items(typ:typ);
  if (v1 != '' && nam != '')
    v1 = nam + ': ' + v1;
  if (v1 != '')
    v1 = v1 + '\n';
  return v1;
}

if(netop_each_found()){

  local_var vals;
  vals = '';

  vals += named_items(nam:'host', typ:0);
  vals += named_items(nam:'user', typ:9);
  vals += named_items(nam:'', typ:8);
  vals += named_items(nam:'', typ:17);
  vals += named_items(nam:'', typ:4);
  vals += named_items(nam:'', typ:1);
  if(((ord(netop_kb_val[63]) & 0x01) == 1) || (vals != '') ||
      eregmatch(pattern:"([^12]10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:named_items(nam:'address', typ:2))) {
    vals += named_items(nam:'address', typ:2);
  }

  if(vals != ''){
    if(netop_prod_typ[0] == 'RGST'){
      vals = '\nDanware ' + netop_prod_nam + ' information disclosure.\n\n' +
             'The following information is made publicly visible for use' +
             ' by NetOp host programs requesting help:\n\n' +
             vals + '\n' +
             'You can control access to this information by' +
             ' removing help services from the program' +
             ' options or by reducing the set of' +
             ' preinitialized communication profiles\n';
    } else if (netop_prod_typ[0] != 'S'){
      vals = '\nDanware ' + netop_prod_nam + ' information disclosure.\n\n' +
             'The following information is made publicly visible for' +
             ' easy network browsing from NetOp Guest:\n\n' +
             vals + '\n' +
             'Solution: If using a version of the software prior to 7.65 build 2004278, then it is necessary to upgrade to correct this issue. Simply use the built-in WebUpdate feature or download the update from http://www.netop.com.\n\nFor all other versions, you can turn this feature off by unchecking the "Public Host Name" check box in the program options (on the host name tab) and restarting the communication layer from the action menu or toolbar.\n\nAdditional information is available from http://www.corsaire.com/advisories/c040619-001.txt\n\n';
    } else {
      vals = '\nDanware ' + netop_prod_nam + ' information disclosure.\n\n' +
             'The following information is made publicly visible on the' +
             ' classroom network so the Teacher and Student' +
             ' can see each other in the class:\n\n' +
             vals + '\n' +
             'If this information is visible from outside' +
             ' the schools network, you should reconfigure' +
             ' your firewall to limit access to this port' +
             ' to those students and teachers who' +
             ' are participating from their homes etc.\n';
    }
    security_message(proto: proto_nam, port: port, data: vals);
  }
}

exit(0);
