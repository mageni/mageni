###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ca_etrust_scm_mult_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# CA eTrust SCM Multiple HTTP Gateway Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800101");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2541");
  script_bugtraq_id(29528);
  script_name("CA eTrust SCM Multiple HTTP Gateway Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30518");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-035/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-036/");
  script_xref(name:"URL", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36408");

  script_tag(name:"affected", value:"CA eTrust Secure Content Manager version 8.0 - Windows (Any).");

  script_tag(name:"insight", value:"The flaws are due to

  - boundary error in the HTTP Gateway service (icihttp.exe running on
  port 8080), when converting content of an FTP request listing from raw text to HTML.

  - insufficient bounds checking on certain FTP requests by sending a specially
  crafted FTP requests containing an overly long LIST/PASV commands that can cause stack-based buffer overflow.");

  script_tag(name:"summary", value:"The host is installed with CA eTrust Secure Content Manager which
  is prone to arbitrary code execution and DoS Vulnerabilities.");

  script_tag(name:"solution", value:"Apply patch QO99987.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code or
  compromise complete system under the system context or denying of service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!registry_key_exists(key:"SOFTWARE\ComputerAssociates\eTrust\SCM")){
  exit(0);
}

scmVer = registry_get_sz(item:"Version", key:"SOFTWARE\ComputerAssociates\eTrust Common Services");
if(!scmVer){
  exit(0);
}

if(egrep(pattern:"^([0-7]\..*|8\.0\.([01]?[0-9]|2[0-8]))$", string:scmVer)){
  report = report_fixed_ver(installed_version:scmVer, fixed_version:"See references");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);