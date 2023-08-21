var popup = document.getElementById("shoppingCart");

var bt = document.getElementById("bt");

var pass = document.getElementById("pass");

function removeHidden() {
    var popup = document.getElementById("shoppingCart");
    popup.classList.remove("hidden");
}

function addHidden() {
    var popup = document.getElementById("shoppingCart");
    popup.classList.add("hidden");
}



function VerifyData() {
    var p1 = document.getElementById("newPass").value;
    var p2 = document.getElementById("newPass2").value;
    if (p1 != p2) {
        alert("As passwords não coincidem")
    }
}  
