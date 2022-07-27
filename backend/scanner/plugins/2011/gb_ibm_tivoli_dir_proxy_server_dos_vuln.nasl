###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_proxy_server_dos_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# IBM Tivoli Directory Proxy Server Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801824");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-4217");
  script_bugtraq_id(44604);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IBM Tivoli Directory Proxy Server Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42083");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2861");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Nov/1024670.html");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IO13364");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IO13282");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_mandatory_keys("IBM/TDS/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash an affected server,
  creating a denial of service condition.");
  script_tag(name:"affected", value:"IBM Tivoli Directory Server (TDS) 6.0.0.x before 6.0.0.8-TIV-ITDS-IF0007
  and 6.1.x before 6.1.0-TIV-ITDS-FP0005.");
  script_tag(name:"insight", value:"The flaw is is caused by an error in the Proxy server when constructing LDAP
  search requests, which could allow remote attackers to crash an affected
  server by sending an unbind operation during a page results search.");
  script_tag(name:"solution", value:"Apply interim fix 6.0.0.8-TIV-ITDS-IF0007 or 6.1.0-TIV-ITDS-FP0005.");

  script_tag(name:"summary", value:"The host is running IBM Tivoli Directory Server and is prone
  to denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

tdsVer = get_kb_item("IBM/TDS/Ver");
if(!tdsVer){
  exit(0);
}

if(version_in_range(version: tdsVer, test_version: "6.0", test_version2:"6.0.0.8") ||
   version_in_range(version: tdsVer, test_version: "6.1", test_version2:"6.1.0.5")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
