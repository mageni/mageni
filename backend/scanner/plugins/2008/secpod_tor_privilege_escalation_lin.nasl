###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_privilege_escalation_lin.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# TOR Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) SecPod http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900424");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5397", "CVE-2008-5398");
  script_bugtraq_id(32648);
  script_name("TOR Privilege Escalation Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.torproject.org");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker gain privileges and escalate
  the privileges in malicious ways.");

  script_tag(name:"affected", value:"Tor version 0.2.0.31 or prior.");

  script_tag(name:"insight", value:"The flaws are due to,

  - an application does not properly drop privileges to the primary groups
  of the user specified by the User Parameter.

  - a ClientDNSRejectInternalAddresses configuration option is not always
  enforced which weaknesses the application security.");

  script_tag(name:"solution", value:"Upgrade to the latest version 0.2.0.32.");

  script_tag(name:"summary", value:"This host is installed with TOR and is prone to Privilege
  Escalation vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Tor/Linux/Ver");
if(ver)
{
  if(version_is_less_equal(version:ver, test_version:"0.2.0.31")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
