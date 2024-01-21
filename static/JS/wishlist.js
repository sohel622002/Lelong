    function getCookie(name) {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length == 2) return parts.pop().split(';').shift();
    }

    function setCookie(name, value) {
      document.cookie = `${name}=${value}; path=/;SameSite=None; Secure`;
    }

function addTag(tagId) {
  console.log(typeof tagId);

  // Parse the existing tags from the cookie
  const cookieValue = getCookie('tags');
  const tags = cookieValue ? JSON.parse(cookieValue) : [];

  console.log(tags);

  // Convert tagId to an integer
  const parsedTagId = parseInt(tagId);

  // Check if parsedTagId is a valid integer
  if (!isNaN(parsedTagId) && Number.isInteger(parsedTagId)) {
    // Check if the parsedTagId is not already in the array
    if (!tags.includes(parsedTagId)) {
      console.log("Adding tag");
      tags.push(parsedTagId);
    } else {
      console.log("It already includes");
    }

    // Update the cookie with the modified list
    setCookie('tags', JSON.stringify(tags));
  } else {
    console.error("Invalid tagId. Not an integer.");
  }
}



function removeTag(button) {
  // Extract the data-id from the clicked button
  const tagId = button.dataset.id;

  // Retrieve the existing tags from the cookie
  const cookieValue = getCookie('tags');
  const tags = cookieValue ? JSON.parse(cookieValue) : [];

  console.log(typeof tagId);

  // Find the index of the tagId in the array
  const index = tags.indexOf(tagId);

  if (index !== -1) {
    // Remove the tagId from the array
    tags.splice(index, 1);

    // Update the cookie with the modified list
    setCookie('tags', JSON.stringify(tags));
  } else {
    console.error("Tag not found in the array.");
  }

  // Redirect to '/wishlist'
  window.location.href = '/wishlist';
}


    function displayTags() {
      // Retrieve the existing tags from the cookie
      const cookieValue = getCookie('tags');
      const tags = cookieValue ? JSON.parse(cookieValue) : [];

      console.log(tags);
    }

