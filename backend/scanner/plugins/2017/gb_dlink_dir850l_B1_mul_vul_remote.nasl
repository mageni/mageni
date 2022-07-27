###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir850l_B1_mul_vul_remote.nasl 12439 2018-11-20 13:01:33Z cfischer $
#
# D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability (remote)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107243");
  script_version("$Revision: 12439 $");
  script_cve_id("CVE-2017-14417", "CVE-2017-14418");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 14:01:33 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability (remote)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html");

  script_tag(name:"summary", value:"D-Link 850L Firmware B1 is vulnerable to Admin Disclosure Vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted HTTP POST requests and check the answers.");

  script_tag(name:"insight", value:"The webpage ip_of_router/register_send.php doesn't check the authentication of the user, thus an attacker can abuse this webpage to
  gain control of the device. This webpage is used to register the device to the myDlink cloud infrastructure.");

  script_tag(name:"impact", value:"Remote attacker can retrieve the admin password and gain full access.");

  script_tag(name:"affected", value:"D-Link DIR 850L Rev B1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # We shouldn't create user accounts on remote devices...