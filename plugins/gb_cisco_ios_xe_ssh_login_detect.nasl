###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS XE Detection (SSH-Login)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.105658");
  script_version("2020-12-08T07:01:29+0000");
  script_tag(name:"last_modification", value:"2020-12-08 07:01:29 +0000 (Tue, 08 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-05-09 15:41:31 +0200 (Mon, 09 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco IOS XE Detection (SSH-Login)");

  script_tag(name:"summary", value:"SSH login based detection of Cisco IOS XE.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  exit(0);
}

include("ssh_func.inc");

if (!show_ver = get_kb_item("cisco/show_version"))
  exit(0);

if (show_ver !~ 'IOS[ -]XE Software.*,')
  exit(0);

port = get_kb_item("cisco/ssh-login/port");

version = "unknown";
model = "unknown";
image = "unknown";

set_kb_item(name: "cisco/ios_xe/detected", value: TRUE);
set_kb_item(name: "cisco/ios_xe/ssh-login/port", value: port);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/concluded", value: show_ver);

sv = split(show_ver, keep: FALSE);

foreach line (sv) {
  if (line =~ '^.*IOS[ -](XE)?.*Version( Denali)? [0-9.]+') {
    vers = eregmatch(pattern: "Version( Denali)? ([^ ,\r\n]+)", string: line);
    break;
  }
}

if (!isnull(vers[2]))
  version = vers[2];

if (show_ver =~ 'Cisco IOS Software, ASR[0-9]+') {
  mod = eregmatch(pattern: 'Cisco IOS Software, (ASR[0-9]+)', string: show_ver);
  if (!isnull(mod[1]))
    model = mod[1];
} else {
  mod = eregmatch(pattern: "cisco ([^\(]+) \([^\)]+\) processor", string: show_ver);
  if (!isnull(mod[1]))
    model = mod[1];
}

img = eregmatch(pattern: "\(([^)]+)\), *Version", string: show_ver);
if (!isnull(img[1]))
  image = img[1];

set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/image", value: image);

exit(0);
