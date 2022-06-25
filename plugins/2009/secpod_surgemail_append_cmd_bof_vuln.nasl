###############################################################################
# OpenVAS Vulnerability Test
#
# SurgeMail 'APPEND' Command Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900840");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7182");
  script_bugtraq_id(30000);
  script_name("SurgeMail 'APPEND' Command Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30739/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496482");
  script_xref(name:"URL", value:"http://www.netwinsite.com/surgemail/help/updates.htm");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_surgemail_detect.nasl");
  script_mandatory_keys("SurgeMail/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to cause a
  Denial of Service and possibly execute arbitrary code in the victim's system.");
  script_tag(name:"affected", value:"SurgeMail version prior to 3.9g2");
  script_tag(name:"insight", value:"Buffer overflow in the IMAP service is caused due the way it handles the
  APPEND command which can be exploited via a long first argument.");
  script_tag(name:"solution", value:"Upgrade to SurgeMail version 3.9g2 or later.");
  script_tag(name:"summary", value:"This host is running SurgeMail and is prone to Buffer Overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

surgemailVer = get_kb_item("SurgeMail/Ver");
if(!surgemailVer)
  exit(0);

if(version_is_less(version:surgemailVer, test_version:"3.9.g2")){
  security_message(port:0);
}
