###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_server_mult_xss_vuln_dec09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# VMware Server Multiple Cross-Site Scripting Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900896");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3731");
  script_bugtraq_id(37346);
  script_name("VMware Server Multiple Cross-Site Scripting Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37460/");
  script_xref(name:"URL", value:"http://www.webworks.com/Security/2009-0001/");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0017.html");
  script_xref(name:"URL", value:"http://kb.vmware.com/kb/1016594");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Server/Win/Ver", "VMware/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will lets attackers to cause a Denial of Service, or
  compromise a user's system.");

  script_tag(name:"affected", value:"VMware Server version 2.0.2 on Windows.");

  script_tag(name:"insight", value:"- Multiple vulnerabilities can be exploited to disclose sensitive information,
  conduct cross-site scripting attacks, manipulate certain data, bypass certain
  security restrictions, cause a DoS, or compromise a user's system.

  - Certain unspecified input passed to WebWorks help pages is not properly
  sanitised before being returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"summary", value:"This host is installed with VMWare Server that is vulnerable to
  multiple Cross-Site Scripting vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(version_is_equal(version:vmserVer, test_version:"2.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
