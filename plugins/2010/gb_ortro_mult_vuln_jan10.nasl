###############################################################################
# OpenVAS Vulnerability Test
#
# Ortro Multiple Unspecified Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800981");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4519");
  script_name("Ortro Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://www.ortro.net/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54026");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3057");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ortro_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ortro/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker Disable/Lock a host and
  to perform scp transfer between two remote hosts.");

  script_tag(name:"affected", value:"Ortro version prior to 1.3.4.");

  script_tag(name:"insight", value:"The flaw is caused by unspecified errors with unknown impact and attack
  vectors.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Ortro version 1.3.4.");

  script_tag(name:"summary", value:"The host has Ortro installed and is prone to multiple Unspecified
  vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

ortroPort = get_http_port(default:80);

ortroVer = get_kb_item("www/"+ ortroPort + "/Ortro");
if(!ortroVer)
  exit(0);

ortroVer  = eregmatch(pattern:"^(.+) under (/.*)$", string:ortroVer);
if(ortroVer[1] != NULL)
{
  if(version_is_less(version:ortroVer[1], test_version:"1.3.4")){
    security_message(ortroPort);
  }
}
