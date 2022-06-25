###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_systemtap_shell_cmd_injection_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# SystemTap 'stap-server' Remote Shell Command Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902017");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4273");
  script_name("SystemTap 'stap-server' Remote Shell Command Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38154");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0169");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_family("General");
  script_mandatory_keys("SystemTap/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow rmote attackers to inject and execute
malicious shell commands or compromise a system.");
  script_tag(name:"affected", value:"SystemTap versions prior to 1.1");
  script_tag(name:"insight", value:"The flaw is due to input validation error in the 'stap-server' component
when processing user-supplied requests.");
  script_tag(name:"solution", value:"Upgrade to version 1.1 or later");
  script_tag(name:"summary", value:"This host has SystemTap installed and is prone to Arbitrary Command
Execution vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://sourceware.org/systemtap/");
  exit(0);
}


include("version_func.inc");

systapVer = get_kb_item("SystemTap/Ver");
if(systapVer != NULL)
{
  if(version_is_less(version:systapVer, test_version:"1.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}


