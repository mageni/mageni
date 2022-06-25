###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_server_mult_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# IBM Tivoli Directory Server Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802224");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2758", "CVE-2011-2759");
  script_bugtraq_id(48512);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IBM Tivoli Directory Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45107");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24030320");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_mandatory_keys("IBM/TDS/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.");
  script_tag(name:"affected", value:"IBM Tivoli Directory Server (TDS) 6.2 before 6.2.0.3-TIV-ITDS-IF0004");
  script_tag(name:"insight", value:"- IDSWebApp in the Web Administration Tool not restricting access to LDAP
    Server log files, which allows remote attackers to obtain sensitive
    information via a crafted URL.

  - The login page of IDSWebApp in the Web Administration Tool does not have
    an off autocomplete attribute for authentication fields, which makes it
    easier for remote attackers to obtain access by leveraging an unattended
    workstation.");
  script_tag(name:"summary", value:"The host is running IBM Tivoli Directory Server and is prone
  to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Apply cumulative interim fix 6.2.0.3-TIV-ITDS-IF0004.

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

tdsVer = get_kb_item("IBM/TDS/Ver");
if(!tdsVer){
  exit(0);
}

if(version_in_range(version:tdsVer, test_version:"6.20", test_version2:"6.20.0.2")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
