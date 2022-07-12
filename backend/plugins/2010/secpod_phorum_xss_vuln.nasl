###############################################################################
# OpenVAS Vulnerability Test
#
# Phorum Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902179");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1629");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Phorum Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.facebook.com/note.php?note_id=371190874581");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/05/16/2");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/05/18/11");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("phorum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phorum/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.");

  script_tag(name:"affected", value:"Phorum version prior to 5.2.15.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade Phorum to 5.2.15 or later.");

  script_tag(name:"summary", value:"This host is running Phorum and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in handling email address.

  NOTE: Further information is not available.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

phorumPort = get_http_port(default:80);

phorumVer = get_kb_item(string("www/", phorumPort, "/phorum"));
phorumVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phorumVer);
if(!phorumVer[1]){
  exit(0);
}

if(version_is_less(version:phorumVer[1], test_version:"5.2.15")){
  security_message(phorumPort);
}
