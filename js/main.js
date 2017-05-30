

            //dragable
            // $( function() {
            //         $("#comment").draggable();
            //       } );
            // //like function
            // $("#like").click(function(evt){
            //     $(this).attr("disabled", "disabled");
            // });
            //
            // // comment function
            // $("#comment").click(function(evt){
            //
            //     // $("comment").attr("disabled", "disabled");
            //     $(this).attr("disabled", "disabled");
            //     var textarea_Comment = $("<textarea />").addClass("textComment");
            //     var divComment = $("<div/>").append(textarea_Comment).addClass("col-xs-12");
            //     var buttonComment = $("<button>Done</button>").addClass("btn btn-primary pull-right").click(function(evt){
            //         //add comment to individul page
            //             buttonComment.detach();
            //             textarea_Comment.detach();
            //             $("#comment").removeAttr("disabled");
            //     });
            //     $("#text").append(divComment).append(buttonComment);
            // });

            //LogoutHandler

            //get id
            function render(){
                window.location.reload();
            }
            function reply_click(clicked_id)
            {
                btnid = clicked_id;

                btnid_sub = btnid.substring(0, 4);
                btnid_sub_comm=btnid.substring(8);
                btnid_sub_dele=btnid.substring(6);
                if(btnid_sub == "like"){
                    //like function
                    // console.log("loooooo");


                        $("#"+ btnid).attr("disabled", "disabled");


                }
                else if(btnid_sub === "comm"){
                    // comment function
                        $("#"+ btnid).attr("disabled", "disabled");
                        var textarea_Comment = $("<textarea />").addClass("textComment");
                        var divComment = $("<div/>").append(textarea_Comment).addClass("col-md-12");
                        var buttonComment = $("<button>Done</button>").addClass("btn btn-primary pull-right").click(function(evt){
                            //add comment to individul page
                            // postid = btnid.substring(7);
                            // cmt = $(".textComment").val();
                            //     cmt = Comment(
                            //         postid = postid,
                            //         cmt= cmt)
                            //     cmt.put()
                                buttonComment.detach();
                                textarea_Comment.detach();
                                $("#"+ btnid).removeAttr("disabled");
                        });
                        $("#text"+ btnid_sub_comm).append(divComment).append(buttonComment);
                }else if(btnid_sub === "dele"){
                    // post = Post.get_by_id(int(id))
                    // post.key().delete();
                }else if (btnid_sub === "forw") {
                    render();
                }
            }
            $(document).ready(function() {
                var userstatus = $("#logincheck").text();
                //LogoutHandler

                if (userstatus === "Welcome Visit"){
                    $("#logout").hide();

                }else{
                    $("#login").hide();
                }
            });
            // var un = "{{username}}";

            // if (un != ""){
            //     $("#login").text(un).attr("href","/sparkle/{{username}}")
            // }
