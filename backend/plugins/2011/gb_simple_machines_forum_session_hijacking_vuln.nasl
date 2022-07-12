###############################################################################
# OpenVAS Vulnerability Test
#
# Simple Machines Forum Session Hijacking Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802334");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_bugtraq_id(49078);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Simple Machines Forum Session Hijacking Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69056");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17637/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMF/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information such as user's session credentials and may aid in further attacks.");

  script_tag(name:"affected", value:"Simple Machines Forum (SMF) 2.0");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of user's sessions,
  allowing a remote attacker to hijack a valid user's session via a specially crafted link.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is installed with Simple Machines Forum and is prone
  to session hijacking vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

smfPort = get_http_port(default:80);

ver = get_version_from_kb(port:smfPort, app:"SMF");
if(!ver)
  exit(0);

if(version_is_equal(version:ver, test_version:"2.0")){
  security_message(smfPort);
}
