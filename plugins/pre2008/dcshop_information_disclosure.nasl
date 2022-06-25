# OpenVAS Vulnerability Test
# $Id: dcshop_information_disclosure.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: DCShop exposes sensitive files
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 by Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10718");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2889);
  script_cve_id("CVE-2001-0821");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("DCShop exposes sensitive files");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5RP0N2K4KE.html");

  script_tag(name:"solution", value:"1. Rename following directories to something hard to guess:

  - Data

  - User_carts

  - Orders

  - Auth_data

  2. Make these changes to dcshop.setup and dcshop_admin.setup.

  - In dcshop.setup, modify:

  $datadir = '$cgidir/Data'

  $cart_dir = '$cgidir/User_carts'

  $order_dir = '$cgidir/Orders'

  - In dcshop_admin.setup, modify:

  $password_file_dir = '$path/Auth_data'

  3. Rename dcshop.setup and dcshop_admin.setup to something difficult to guess.
  For example, dcshop_4314312.setup and dcshop_admin_3124214.setup

  4. Edit dcshop.cgi, dcshop_admin.cgi, and dcshop_checkout.cgi and modify the
  require statement for dcshop.setup and dcshop_admin.setup. That is:

  - In dcshop.cgi, modify

  require '$path/dcshop.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  - In dcshop_admin.cgi, modify

  require '$path/dcshop.setup'

  require '$path/dcshop_admin.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  require '$path/dcshop_admin_3124214.setup'

  - In dcshop_checkout.cgi, modify

  require '$path/dcshop.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  5. Save following file as index.html and upload it to your
  /cgi-bin/dcshop directory, thereby hiding directory listing. On
  NT servers, you may have to rename this file to default.htm.

  This page show 'Internal Server Error' so it is not an error page...
  it's just an index.html file to HIDE directories.

  6. Replace your current files with above files.");

  script_tag(name:"summary", value:"We detected a vulnerable version of the DCShop CGI.
  This version does not properly protect user and credit card information.
  It is possible to access files that contain administrative passwords,
  current and pending transactions and credit card information (along with name,
  address, etc).");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

program[0] = "/dcshop.pl";
program[1] = "/dcshop.cgi";

orders[0] = "/Orders/orders.txt";
orders[1] = "/orders/orders.txt";

Auth[0] = "/Auth_data/auth_user_file.txt";
Auth[1] = "/auth_data/auth_user_file.txt";

unsafe_url_count = 0;

foreach dir (make_list_unique(cgi_dirs(port:port), "/dcshop", "/DCshop")) {

  if(dir == "/")
  dir = "";

  for(j = 0; program[j]; j++) {
    url = string(dir, program[j]);
    if (is_cgi_installed_ka(item:url, port:port)) {
      unsafe_url_count = 0;
      for(k = 0; orders[k]; k++) {
        orders_url = string(dir, orders[k]);
        success = is_cgi_installed_ka(item:orders_url, port:port);
        if(success) {
          unsafe_urls[unsafe_url_count] = string("DCShop orders file: ", orders_url);
          unsafe_url_count = unsafe_url_count + 1;
        }
      }

      flag = 0;
      for(k = 0; Auth[k]; k++) {
        auth_url = string(dir, Auth[k]);
        success = is_cgi_installed_ka(item:auth_url, port:port);
        if (success) {
          flag = 1;
          unsafe_urls[unsafe_url_count] = string("DCShop authentication file: ", auth_url);
          unsafe_url_count = unsafe_url_count + 1;
        }
      }
    }
  }
}

if(unsafe_url_count > 0) {

  data = string("\n\n\nThe following files are affected:\n\n");
  for(i = 0; i < unsafe_url_count; i++)
    data = string(data, unsafe_urls[i], "\n");
  security_message(port:port, data:data);
  exit(0);
}

exit(99);