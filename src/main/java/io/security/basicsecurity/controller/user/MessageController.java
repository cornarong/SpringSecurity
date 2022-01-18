package io.security.basicsecurity.controller.user;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/messages")
    public String messages() throws Exception{
        return "user/messages";
    }

    @ResponseBody
    @PostMapping("/api/messages")
    public ResponseEntity apiMessage() throws Exception {
        return ResponseEntity.ok().body("ok");
    }

//    @PostMapping("/api/messages")
//    @ResponseBody
//    public String apiMessage(){
//        return "messages ok";
//    }
}
