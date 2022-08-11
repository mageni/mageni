###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_cmd_exec_n_xss_vuln_lin.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# Opera Web Browser Command Execution and XSS Vulnerabilities (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800049");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4794", "CVE-2008-4795");
  script_bugtraq_id(31991);
  script_name("Opera Web Browser Command Execution and XSS Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/906/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/907/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary HTML and script code,
  launch cross site scripting attacks on user's browser session when malicious data is being viewed.");

  script_tag(name:"affected", value:"Opera version prior to 9.62 on Linux.");

  script_tag(name:"insight", value:"Flaws are due to,

  - certain parameters passed to the History Search functionality are not
    properly sanitised before being used.

  - an error exists in the handling of javascript URLs in the Links panel.");

  script_tag(name:"solution", value:"Upgrade to Opera 9.62 or later.");

  script_tag(name:"summary", value:"The host is installed with Opera Web Browser and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.62")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
