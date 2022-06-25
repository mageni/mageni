###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_strongswan_n_openswan_dos_vuln_jun09.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# StrongSwan/Openswan Denial Of Service Vulnerability June-09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900386");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2185");
  script_bugtraq_id(35452);
  script_name("StrongSwan/Openswan Denial Of Service Vulnerability June-09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35522");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1639");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_openswan_detect.nasl", "gb_strongswan_detect.nasl");
  script_mandatory_keys("Openswan_or_StrongSwan/Lin/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause pluto IKE daemon crash.");

  script_tag(name:"affected", value:"OpenSwan version 2.6 before 2.6.22 and 2.4 before 2.4.15

  strongSwan version 2.8 before 2.8.10, 4.2 before 4.2.16, and 4.3 before 4.3.2");

  script_tag(name:"insight", value:"- Error in 'ASN.1' parser in pluto/asn1.c, libstrongswan/asn1/asn1.c, and
  libstrongswan/asn1/asn1_parser.c is caused via an 'X.509' certificate
  with crafted Relative Distinguished Names (RDNs), a crafted UTCTIME string,
  or a crafted GENERALIZEDTIME string.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to OpenSwan version 2.6.22 or 2.4.15

  Upgrade to strongSwan version 2.8.10 or 4.2.16 or 4.3.2.");

  script_tag(name:"summary", value:"The host is installed with strongSwan/Openswan and is prone to Denial of
  Service vulnerability.");

  exit(0);
}

include("version_func.inc");

oswanVer = get_kb_item("Openswan/Ver");
if(oswanVer)
{
  if(version_in_range(version:oswanVer, test_version:"2.6", test_version2:"2.6.21")||
     version_in_range(version:oswanVer, test_version:"2.4", test_version2:"2.4.14")){
    security_message(port:0);
  }
}

sswanVer = get_kb_item("StrongSwan/Ver");
if(sswanVer)
{
  if(version_in_range(version:sswanVer, test_version:"2.8", test_version2:"2.8.9") ||
     version_in_range(version:sswanVer, test_version:"4.2", test_version2:"4.2.15")||
     version_in_range(version:sswanVer, test_version:"4.3", test_version2:"4.3.1")){
    security_message(port:0);
  }
}
