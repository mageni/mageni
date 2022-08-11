###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_li_element_dos_vuln_sep09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Microsoft Internet Explorer 'li' Element DoS Vulnerability - Sep09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800872");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3019");
  script_bugtraq_id(36070);
  script_name("Microsoft Internet Explorer 'li' Element DoS Vulnerability - Sep09");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9455");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/36070-1.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/36070-3.txt");
  script_xref(name:"URL", value:"https://connect.microsoft.com/IE/feedback/ViewFeedback.aspx?FeedbackID=338599");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version", "SMB/WinXP/ServicePack");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers can cause the application
  to crash.");

  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 6.x on Windows XP SP2/SP3");

  script_tag(name:"insight", value:"Error exists when application fails to handle a crafted JavaScript code, that
  calls 'createElement' to create an instance of the 'li' element, and then calls 'setAttribute' to set the value attribute.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Internet Explorer version 8 or 8 beta 2.");

  script_tag(name:"summary", value:"This host has Internet Explorer installed and is prone to Denial
  of Service vulnerability.");

  exit(0);
}

include("smb_nt.inc");

SP = get_kb_item("SMB/WinXP/ServicePack");
if(("Service Pack 3" >< SP) || ("Service Pack 2" >< SP))
{
  ieVer = get_kb_item("MS/IE/Version");
  if(ieVer =~ "^6\..*"){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
