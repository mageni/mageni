#############################################################################
# OpenVAS Vulnerability Test
# Description: Windows Messenger is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2012-05-30
#  - Included the detect script.
#  - Checking for the versions affected.
#  - Modified the description.
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
###################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11429");
  script_version("2022-02-15T16:28:09+0000");
  script_bugtraq_id(4028, 4316, 4675, 4827, 668);
  script_cve_id("CVE-1999-1484", "CVE-2002-0228", "CVE-2002-0472");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-16 11:08:17 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_name("Microsoft Windows Messenger Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("Windows");
  script_dependencies("secpod_windows_messenger_detect.nasl");
  script_mandatory_keys("Microsoft/MSN/Messenger/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8084");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8582");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/setupbbs.txt");

  script_tag(name:"summary", value:"Microsoft Windows Messenger is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain
  security restrictions, execute arbitrary code in the context of the browser or cause a denial of
  service.");

  script_tag(name:"affected", value:"- Microsoft MSN Messenger Service 1.x, 2.0.x, 2.2.x, 3.0.x, 3.6.x

  - Microsoft MSN Messenger Service 4.0.x to 4.6.x");

  script_tag(name:"insight", value:"The following flaws exist:

  - Buffer overflow in Setup ActiveX control (setupbbs.ocx), allows ttacker to execute commands via
  the methods vAddNewsServer or bIsNewsServerConfigured.

  - An error in 'ActiveX' object allows attacker to disclosure information.

  - An error in the authentication mechanisms, allows remote attacker to spoof messages.

  - An error in 'Font' tag and in 'Invite' request allows remote attacker to cause denial of service.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Microsoft/MSN/Messenger/Ver"))
  exit(0);

if(version_in_range(version:vers, test_version:"1.0", test_version2:"2.0.0.085") ||
   version_in_range(version:vers, test_version:"2.2", test_version2:"3.0.0.286") ||
   version_in_range(version:vers, test_version:"3.6", test_version2:"3.6.0.039") ||
   version_in_range(version:vers, test_version:"4.0", test_version2:"4.6.0.083")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);