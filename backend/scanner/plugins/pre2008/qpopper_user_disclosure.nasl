# OpenVAS Vulnerability Test
# $Id: qpopper_user_disclosure.nasl 13293 2019-01-25 12:15:55Z cfischer $
# Description: QPopper Username Information Disclosure
#
# Authors:
# Scott Shebby scotts@scanalert.com
# based on Thomas Reinke's qpopper2.nasl
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12279");
  script_version("$Revision: 13293 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 13:15:55 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7110);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("QPopper Username Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Scott Shebby");
  script_family("General");
  script_dependencies("popserver_detect.nasl");
  script_require_ports("Services/pop3", 110, 995);
  script_mandatory_keys("pop3/qpopper/detected");

  script_tag(name:"summary", value:"The remote server appears to be running a version of QPopper
  that is older than 4.0.6.");

  script_tag(name:"impact", value:"Versions older than 4.0.6 are vulnerable to a bug where remote
  attackers can enumerate valid usernames based on server responses during the authentication process.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("pop3_func.inc");

port = get_pop3_port(default:110);
banner = get_pop3_banner(port:port);
if(!banner || "Qpopper" >!< banner)
  exit(0);

if(ereg(pattern:".*Qpopper.*version ([0-3]\.*|4\.0\.[0-5][^0-9]).*", string:banner, icase:TRUE)){
  security_message(port:port);
  exit(0);
}

exit(99);