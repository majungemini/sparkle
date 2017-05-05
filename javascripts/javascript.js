//comment add textarea


$("#comment").click(function(evt){
    var textarea_Comment = $("<textarea />").addClass("textComment");
    $("#comment").append(textarea_Comment);
});
