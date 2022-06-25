###############################################################################
# OpenVAS Vulnerability Test
#
# Sun VirtualBox 'VBoxNetAdpCtl' Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901052");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3692");
  script_bugtraq_id(36604);
  script_name("Sun VirtualBox 'VBoxNetAdpCtl' Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36929");
  script_xref(name:"URL", value:"http://www.virtualbox.org/wiki/Changelog");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2845");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-268188-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary commands
  with root privileges via specially crafted arguments.");
  script_tag(name:"affected", value:"Sun VirtualBox version 3.x before 3.0.8");
  script_tag(name:"insight", value:"The flaw is due to the 'VBoxNetAdpCtl' configuration tool improperly
  sanitising arguments before passing them in calls to 'popen()'.");
  script_tag(name:"solution", value:"Upgrade to Sun VirtualBox version 3.0.8.");
  script_tag(name:"summary", value:"This host is installed with Sun VirtualBox and is prone to Privilege
  Escalation vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:"cpe:/a:sun:virtualbox"))
  exit(0);

if(ver =~ "^3\." && version_is_less(version:ver, test_version:"3.0.8")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
