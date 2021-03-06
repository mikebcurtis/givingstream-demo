ruleset givingStream {
  meta {
    name "GivingStream"
    description <<
      The listener for GivingStream
    >>
    author ""

    key twilio {"account_sid" : "ACff7946d590c683a85666c3264d9a6166",
                "auth_token"  : "ce46e850578831e1d4cb146ff3b5abbe"
    }
     
    use module a8x115 alias twilio with twiliokeys = keys:twilio()
  }
  dispatch {
  }
  global {
    givingStreamUrl = "http://ec2-54-80-167-106.compute-1.amazonaws.com/";
    eventChannel = "BA30DA34-C4BB-11E3-952F-E822D43F553C";
    myZipcode = "84604";
  }
  
  rule getUserId {
    select when explicit getUserId
    pre {
      command = event:attr("command");
      body = event:attr("body");
      result = http:post(givingStreamUrl + "users");
      content = result.pick("$.content").decode();
      userId = content.pick("$.id").as("str");
    }
    always {
      set ent:userId userId;
      raise explicit event command
        with body = body;
    }
  }

  rule receiveCommand {
    select when twilio command
    pre {
      userId = ent:userId;
      body = event:attr("Body");
      bodyArray = body.split(re/ /);
      command = bodyArray[0].lc();
    }
    if (userId) then {
      send_directive("called") with called = userId;
      noop();
    }
    fired {
      raise explicit event command
        with body = body;
    }
    else {
      raise explicit event getUserId
        with body = body
          and command = command;
    }
  }
  
  rule offer {
    select when explicit offer
    pre {
      userId = ent:userId;
      body = event:attr("body");
      tag = body.extract(re/ #(\w+)\s?/);
      tag = tag[0];
      zipcode = body.extract(re/ z(\d+)\s?/);
      zipcode = zipcode[0];

      description = body.replace(re/#\w+\s?/, "");
      description = description.replace(re/z\d+\s?/, "");
    }
    {
      send_directive("test") with hello = "1." + body + "2." + tag + "3."+zipcode + "4."+description;
      http:post(givingStreamUrl + "offers")
        with body = {
          "location" : zipcode,
          "tag" : tag,
          "description" : description,
          "imgURL" : ""
        } and
        headers = {
          "content-type": "application/json"
        };
    }
  }
  
  rule watch {
    select when explicit watch
    pre {
      userId = ent:userId;
      body = event:attr("body");
      tags = body.extract(re/ #(\w+)\s?/);
      webhook = "http://cs.kobj.net/sky/event/"+eventChannel+"?_domain=givingStream&_name=watchTagAlert";
      joined = tags.join(" ");
    }
    {
      send_directive("testing") with tags = tags and webhook = webhook and userId = userId;
      http:post(givingStreamUrl + "users/" + userId + "/watchtags")
        with body = {
          "watchtags" : tags,
          "webhook" : webhook
        } and
        headers = {
          "content-type": "application/json"
        };
    }
  }
  
  rule stopWatching {
    select when explicit stopwatching
    pre {
      userId = ent:userId;
      body = event:attr("body");
      tags = body.extract(re/ #(\w+)\s?/);
      tag = tags.length() > 0 => tags[0] | '';
    }
    {
      send_directive("stopped") with submitBody = submitBody;
      http:delete(givingStreamUrl + "users/" + userId + "/watchtags/" + tag);
    }
  }

  rule watchTagAlert {
    select when givingStream watchTagAlert
    pre {
      content = event:attr("offer");
      contentDecoded = content.decode();
      location = contentDecoded.pick("$.location").as("str");
      tags = contentDecoded.pick("$.tags");
      tags = tags[0];
      description = contentDecoded.pick("$.description").as("str");
      imgURL = contentDecoded.pick("$.imgURL").as("str");
    }
    if (location == myZipcode) then
    {
      //send_directive("testContent") with testing = tags;
      twilio:send_sms("8015104357", "3852452636", "Tags: " + tags + ". Description: " + description + ". Image: " + imgURL);
    }
  }
  
}
