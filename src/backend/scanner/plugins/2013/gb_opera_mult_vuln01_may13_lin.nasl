###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln01_may13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Opera Multiple Vulnerabilities-01 May13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903389");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3211", "CVE-2013-3210");
  script_bugtraq_id(58864, 59317);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-02 11:20:49 +0530 (Thu, 02 May 2013)");
  script_name("Opera Multiple Vulnerabilities-01 May13 (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/security/advisory/1047");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1215");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation could led to user's accounts being compromised or
  disclose sensitive information that may aid in launching further attacks.");
  script_tag(name:"affected", value:"Opera version before 12.15 on Linux");
  script_tag(name:"insight", value:"- Unspecified error related to 'moderately severe issue'.

  - Does not properly block top-level domains in Set-Cookie headers.");
  script_tag(name:"solution", value:"Upgrade to Opera version 12.15 or later.");
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

if(version_is_less(version:operaVer, test_version:"12.15"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
