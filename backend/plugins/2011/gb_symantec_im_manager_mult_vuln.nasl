###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_im_manager_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Symantec IM Manager Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802252");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-0552", "CVE-2011-0553", "CVE-2011-0554");
  script_bugtraq_id(49738, 49739, 49742);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Symantec IM Manager Multiple Vulnerabilities");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/IM/Manager");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code in the browser, compromise the application, access or modify data, or
  exploit latent vulnerability in the underlying database.");
  script_tag(name:"affected", value:"Symantec IM Manager versions 8.4.17 and prior");
  script_tag(name:"insight", value:"- Input passed to the 'refreshRateSetting' parameter in IMManager/Admin/
    IMAdminSystemDashboard.asp, 'nav' and 'menuitem' parameters in
    IMManager/Admin/IMAdminTOC_simple.asp, and 'action' parameter in
    IMManager/Admin/IMAdminEdituser.asp is not properly sanitised before being
    returned to the user. This can be exploited to execute arbitrary HTML and
    script code in a user's browser session in context of an affected site.

  - Input validation errors exist within the Administrator Console allows
    remote attackers to execute arbitrary code or SQL commands via unspecified
    vectors.");
  script_tag(name:"solution", value:"Upgarade to Symantec IM Manager version 8.4.18 (build 8.4.1405) or later.");
  script_tag(name:"summary", value:"This host is installed with Symantec IM Manager and is prone to
  multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43157");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1026130");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110929_00");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.symantec.com/business/im-manager");
  exit(0);
}


include("version_func.inc");

imVer = get_kb_item("Symantec/IM/Manager");
if(!imVer){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"8.4.1405")) {
  security_message(port:0);
}
