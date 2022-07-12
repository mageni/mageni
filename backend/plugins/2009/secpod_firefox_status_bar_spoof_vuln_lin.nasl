###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_status_bar_spoof_vuln_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Firefox Status Bar Spoofing Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900447");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0253");
  script_name("Firefox Status Bar Spoofing Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7842");
  script_xref(name:"URL", value:"http://security-tracker.debian.net/tracker/CVE-2009-0253");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation will let the attacker spoof the status
  bar information and can gain sensitive information by redirecting the
  authentic user to any malicious URL.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.5 and 2.0.0.18/19 on Linux.");
  script_tag(name:"insight", value:"Firefox doesn't properly handle the crafted URL which is being displayed in
  the user's browser which lets the attacker perform clickjacking attack and
  can spoof the user redirect to a different arbitrary malformed website.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to status bar spoofing vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.getfirefox.com");
  exit(0);
}


firefoxVer = get_kb_item("Firefox/Linux/Ver");
if(firefoxVer =~ "(2.0.0.18|2.0.0.19|3.0.5)"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
