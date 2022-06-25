###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln03_jan13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Opera Multiple Vulnerabilities-03 Jan13 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803145");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-6461", "CVE-2012-6462", "CVE-2012-6463", "CVE-2012-6464",
                "CVE-2012-6465", "CVE-2012-6466", "CVE-2012-6467");
  script_bugtraq_id(57121, 56407, 57120, 57132);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-07 16:09:01 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-03 Jan13 (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1034/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1035/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1033/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1032/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1031/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1030/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1029/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1210/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information.");

  script_tag(name:"affected", value:"Opera version before 12.10 on Linux");

  script_tag(name:"insight", value:"- Internet shortcuts used for phishing in '<img>' elements.

  - Specially crafted WebP images can be used to disclose random chunks
    of memory.

  - Specially crafted SVG images can allow execution of arbitrary code.

  - Cross domain access to object constructors can be used to facilitate
    cross-site scripting.

  - Data URIs can be used to facilitate Cross-Site Scripting.

  - CORS requests can incorrectly retrieve contents of cross origin pages.

  - Certificate revocation service failure may cause Opera to show an
    unverified site as secur.");

  script_tag(name:"solution", value:"Upgrade to Opera version 12.10 or later.");

  script_tag(name:"summary", value:"The host is installed with Opera and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.10")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
